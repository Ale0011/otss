// Package ratelimit implements per-client-IP token buckets.
//
// The hard part is not the bucket, it is deciding which IP the client is.
// A naive `X-Forwarded-For: 1.2.3.4` header must not create a fresh bucket per
// request, so:
//
//   - TRUSTED_PROXIES defaults to empty, meaning the header is ignored entirely
//     and RemoteAddr wins. Spoofing is impossible.
//   - If a reverse proxy is configured, the header is honoured only when the
//     immediate peer is inside one of the trusted CIDRs, and only the
//     right-most *untrusted* hop is used (standard XFF walking).
package ratelimit

import (
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter is a set of independent token buckets keyed by an arbitrary string.
type Limiter struct {
	rate  float64 // tokens per second
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New creates a limiter allowing `burst` immediate requests and refilling at
// `perSecond`.
func New(perSecond, burst float64) *Limiter {
	if perSecond <= 0 {
		perSecond = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    perSecond,
		burst:   burst,
		buckets: make(map[string]*bucket, 4096),
		lastGC:  time.Now(),
	}
}

// Allow consumes one token for key. It returns whether the request may proceed
// and, if not, how long until a token is available.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.gcLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
			b.last = now
		}
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}

	missing := 1 - b.tokens
	wait := time.Duration(missing / l.rate * float64(time.Second))
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return false, wait
}

// gcLocked drops buckets that have been idle long enough to be full again.
// Bounded memory without a separate goroutine.
//
// Recreating a deleted bucket with a full burst is intentional and not a
// bypass: we only delete buckets that have been idle for more than
// burst/rate seconds, at which point continuous refill would already have
// restored them to `l.burst` if they were still in the map. Deleting them
// and recreating them with a full burst is therefore observationally
// identical to keeping them.
func (l *Limiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now
	idle := time.Duration(l.burst/l.rate*float64(time.Second)) + time.Second
	for k, b := range l.buckets {
		if len(l.buckets) <= 1024 {
			break // not under pressure; keep the map warm
		}
		if now.Sub(b.last) > idle {
			delete(l.buckets, k)
		}
	}
}

// ClientIPResolver maps a request to the IP used for rate limiting.
type ClientIPResolver struct {
	trusted []*net.IPNet
}

// NewClientIPResolver parses a comma-separated list of trusted proxy CIDRs.
// An empty list means "trust nothing", which is the safe default.
func NewClientIPResolver(cidrs string) *ClientIPResolver {
	r := &ClientIPResolver{}
	for _, part := range strings.Split(cidrs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				part = part + "/" + itoa(bits)
			}
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			r.trusted = append(r.trusted, n)
		}
	}
	return r
}

func itoa(i int) string {
	if i == 32 {
		return "32"
	}
	return "128"
}

func (r *ClientIPResolver) isTrusted(ip net.IP) bool {
	for _, n := range r.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the address to bucket on. IPv6 peers are keyed by /64.
func (r *ClientIPResolver) ClientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return host
	}

	// No trusted proxies: the socket address is authoritative. Every
	// X-Forwarded-For value is attacker-controlled noise.
	if len(r.trusted) == 0 || !r.isTrusted(peer) {
		return bucketKey(peer)
	}

	// Walk XFF right to left, skipping trusted hops. The first untrusted
	// address we meet is the real client.
	//
	// Values() is used rather than Get(): Get returns only the first header
	// line. A proxy that appends its own X-Forwarded-For header instead of
	// comma-joining into the existing one would otherwise leave the client's
	// spoofed first header as the only thing we look at, and the client could
	// mint a fresh bucket per request by rotating it.
	vals := req.Header.Values("X-Forwarded-For")
	if len(vals) == 0 {
		return bucketKey(peer)
	}
	xff := strings.Join(vals, ",")
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		if r.isTrusted(ip) {
			continue
		}
		return bucketKey(ip)
	}
	return bucketKey(peer)
}

// bucketKey normalizes an IP for use as a limiter key.
func bucketKey(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		// IPv4-mapped addresses must not create a second bucket for an IPv4
		// client, so they are handled by the To4 branch above.
		if v6 := ip.To16(); v6 != nil {
			var mask [16]byte
			copy(mask[:], v6[:8]) // keep the top 64 bits, zero the rest
			return "6:" + net.IP(mask[:]).String() + "/64"
		}
		return ip.String()
	}
	return "4:" + v4.String()
}
