package ratelimit

import (
	"fmt"
	"net/http"
	"testing"
)

func TestBurstThenRefill(t *testing.T) {
	l := New(10, 3)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("k"); !ok {
			t.Fatalf("request %d denied inside burst", i)
		}
	}
	ok, wait := l.Allow("k")
	if ok {
		t.Fatal("4th request allowed beyond burst")
	}
	if wait <= 0 {
		t.Fatal("denied request reported no wait time")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, 1)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first for a denied")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("independent key b denied")
	}
}

func TestResolverIgnoresXFFByDefault(t *testing.T) {
	r := NewClientIPResolver("")
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := r.ClientIP(req); got != "4:203.0.113.9" {
		t.Fatalf("got %q, want the socket address", got)
	}
}

func TestResolverSpoofedXFFStillOneBucket(t *testing.T) {
	r := NewClientIPResolver("")
	l := New(1, 2)
	allowed := 0
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		req.Header.Set("X-Forwarded-For", "10.9.9."+string(rune('0'+i%10)))
		if ok, _ := l.Allow(r.ClientIP(req)); ok {
			allowed++
		}
	}
	if allowed > 2 {
		t.Fatalf("spoofed XFF created %d buckets from one socket", allowed)
	}
}

func TestResolverTrustedProxyWalksRightToLeft(t *testing.T) {
	r := NewClientIPResolver("10.0.0.0/8")
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:443"
	// Client-supplied junk on the left must be ignored, trusted hops skipped,
	// and the right-most untrusted hop returned.
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.4.4.4")

	if got := r.ClientIP(req); got != "4:198.51.100.7" {
		t.Fatalf("got %q, want 4:198.51.100.7", got)
	}
}

func TestResolverIgnoresXFFFromUntrustedPeer(t *testing.T) {
	r := NewClientIPResolver("10.0.0.0/8")
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.99:443"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	if got := r.ClientIP(req); got != "4:198.51.100.99" {
		t.Fatalf("got %q, want the untrusted peer address", got)
	}
}

// A proxy that appends a second X-Forwarded-For header instead of comma-joining
// must not let a client spoof its way to a fresh bucket by controlling the first
// header line. Header.Get only returns the first line, so Values must be joined.
func TestMultiHeaderXFFCannotBypass(t *testing.T) {
	r := NewClientIPResolver("10.0.0.0/8")

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:443"
	req.Header.Add("X-Forwarded-For", "6.6.6.6")      // attacker-controlled first line
	req.Header.Add("X-Forwarded-For", "198.51.100.7") // proxy-appended real client

	if got := r.ClientIP(req); got != "4:198.51.100.7" {
		t.Fatalf("got %q, want the proxy-appended client 4:198.51.100.7", got)
	}

	// The attacker rotating the first header must not produce new keys.
	l := New(1, 2)
	allowed := 0
	for i := 0; i < 15; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.1.2.3:443"
		req.Header.Add("X-Forwarded-For", fmt.Sprintf("9.9.9.%d", i))
		req.Header.Add("X-Forwarded-For", "198.51.100.7")
		if ok, _ := l.Allow(r.ClientIP(req)); ok {
			allowed++
		}
	}
	if allowed > 2 {
		t.Fatalf("rotating the first XFF header yielded %d allows, want <= 2", allowed)
	}
}

// let one host mint unlimited fresh buckets for free. This is the regression
// test for that bypass.
func TestIPv6RotatesInside64ButNotAcross(t *testing.T) {
	r := NewClientIPResolver("")
	l := New(1, 3)

	allowed := 0
	// 300 distinct interface identifiers inside one /64.
	for i := 0; i < 300; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = fmt.Sprintf("[2001:db8:1:2:%x:%x:%x:%x]:443", i>>12, i&0xff, i+1, i+2)
		if ok, _ := l.Allow(r.ClientIP(req)); ok {
			allowed++
		}
	}
	if allowed > 3 {
		t.Fatalf("rotating inside a /64 yielded %d allows, want <= 3", allowed)
	}

	// A different /64 must still get its own bucket.
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:db8:1:3::1]:443"
	if ok, _ := l.Allow(r.ClientIP(req)); !ok {
		t.Fatal("a different /64 should have its own bucket")
	}
}

// An IPv4-mapped IPv6 peer must not be able to double its budget by presenting
// the same host in both forms.
func TestIPv4MappedDoesNotDoubleBudget(t *testing.T) {
	r := NewClientIPResolver("")
	l := New(1, 2)

	a, _ := http.NewRequest(http.MethodGet, "/", nil)
	a.RemoteAddr = "203.0.113.5:1111"
	b, _ := http.NewRequest(http.MethodGet, "/", nil)
	b.RemoteAddr = "[::ffff:203.0.113.5]:2222"

	if r.ClientIP(a) != r.ClientIP(b) {
		t.Fatalf("same host bucketed differently: %q vs %q", r.ClientIP(a), r.ClientIP(b))
	}

	allowed := 0
	for i := 0; i < 10; i++ {
		req := a
		if i%2 == 1 {
			req = b
		}
		if ok, _ := l.Allow(r.ClientIP(req)); ok {
			allowed++
		}
	}
	if allowed > 2 {
		t.Fatalf("dual-form host got %d allows, want <= 2", allowed)
	}
}
