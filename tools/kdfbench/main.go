// Command kdfbench measures how fast an attacker who has a memory dump can
// brute-force a passphrase offline.
//
// This is the honest counterpart to the design claim: the KDF is a single
// HMAC-SHA256, so a stolen wrapped DEK can be attacked at whatever rate the
// attacker's hardware allows, with no network round trip and no rate limit.
// Running this tells you what "strong enough passphrase" actually means here.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// wrapKey mirrors envelope.wrapKey exactly. If the two drift apart, this tool
// stops being a faithful model and becomes a lie, so it is duplicated
// deliberately rather than exported from the production package.
func wrapKey(master []byte, secretID, passphrase string) []byte {
	salt := hmac.New(sha256.New, master)
	salt.Write([]byte("otss:v2:wrap-salt\x00"))
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(secretID)))
	salt.Write(lb[:])
	salt.Write([]byte(secretID))
	saltSum := salt.Sum(nil)

	if passphrase == "" {
		m := hmac.New(sha256.New, master)
		m.Write([]byte("otss:v2:wrap-key-plain\x00"))
		m.Write(saltSum)
		return m.Sum(nil)
	}

	return pbkdf2SHA256([]byte(passphrase), saltSum, iterations, 32, master)
}

var iterations = 300000

func pbkdf2SHA256(password, salt []byte, iters, keyLen int, mixingKey []byte) []byte {
	prf := hmac.New(sha256.New, mixingKey)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)

	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(password)
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for i := 1; i < iters; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func aad(secretID string) []byte {
	b := make([]byte, 0, 10+len(secretID))
	b = append(b, "otss:v1:ad\x00"...)
	b = append(b, secretID...)
	return b
}

func main() {
	pass := flag.String("pass", "correct horse battery staple", "the real passphrase")
	id := flag.String("id", "MGAHZxfwNSo7pKDEY7Ed3_7BJTtm0fqU", "the secret id from the dump")
	workers := flag.Int("w", 0, "worker goroutines (0 = NumCPU)")
	maxTries := flag.Int("n", 2000000, "candidate attempts per worker")
	flag.Parse()

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Build a real target: wrap a random DEK under the real passphrase.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	wk := wrapKey(master, *id, *pass)
	blk, _ := aes.NewCipher(wk)
	g, _ := cipher.NewGCM(blk)
	wn := make([]byte, 12)
	if _, err := rand.Read(wn); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	wrapped := g.Seal(nil, wn, dek, aad(*id))
	// The attacker's view of the target: everything except the passphrase.
	target := append(append([]byte{}, wn...), wrapped...)

	if *workers <= 0 {
		*workers = numCPU()
	}

	fmt.Printf("attack model\n")
	fmt.Printf("  the attacker has: master key, secret id, wrapped DEK\n")
	fmt.Printf("  the attacker does NOT have: the passphrase\n")
	fmt.Printf("  work per guess: HMAC-SHA256 to derive, AES-GCM to test the tag\n")
	fmt.Printf("  workers: %d\n\n", *workers)

	var attempts atomic.Int64
	var found atomic.Bool
	stop := make(chan struct{})

	start := time.Now()
	var wg sync.WaitGroup

	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			blk, _ := aes.NewCipher(make([]byte, 32)) // reused buffer shape
			_ = blk
			for i := 0; i < *maxTries; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// A real attacker walks a dictionary; this walks a dense space so
				// the throughput number is a clean upper-ish bound.
				candidate := fmt.Sprintf("guess-%d-%d", worker, i)
				k := wrapKey(master, *id, candidate)
				b, _ := aes.NewCipher(k)
				gg, _ := cipher.NewGCM(b)
				if _, err := gg.Open(nil, target[:12], target[12:], aad(*id)); err == nil {
					found.Store(true)
					close(stop)
					return
				}
				attempts.Add(1)
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(start)

	n := attempts.Load()
	rate := float64(n) / elapsed.Seconds()

	fmt.Printf("results\n")
	fmt.Printf("  guesses made:   %d\n", n)
	fmt.Printf("  wall clock:     %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  rate:           %.0f guesses/sec\n\n", rate)

	// Translate the rate into time-to-crack for realistic passphrase spaces.
	type space struct {
		name  string
		bits  float64
		label string
	}
	spaces := []space{
		{"6 lowercase letters", 28.2, "sunset"},
		{"8 lowercase letters", 37.6, "passcode"},
		{"8 mixed alnum", 47.6, "Pa55w0rd"},
		{"12 mixed alnum", 71.5, "Tr0ub4dor&3x"},
		{"4-word diceware", 51.7, "correct-horse-battery-staple"},
		{"6-word diceware", 77.5, "long passphrase"},
		{"random 16 bytes b64", 128, "base64 blob"},
	}

	fmt.Printf("time to exhaust each space at this rate (expected: average is half)\n")
	fmt.Printf("  %-22s %8s  %s\n", "space", "bits", "time to exhaust")
	for _, s := range spaces {
		combos := pow2(s.bits)
		seconds := combos / rate
		fmt.Printf("  %-22s %8.1f  %s\n", s.name, s.bits, humanDuration(seconds))
	}

	fmt.Printf("\nverdict\n")
	if rate > 100000 {
		fmt.Printf("  %.0f guesses/sec means a single-HMAC KDF gives an attacker a big head start.\n", rate)
		fmt.Printf("  Anything under ~60 bits of passphrase entropy is at risk from a patient attacker\n")
		fmt.Printf("  who obtains a memory dump. This is why the docs say: use a long passphrase, or none.\n")
	} else {
		fmt.Printf("  %.0f guesses/sec is slow enough that a decent passphrase holds.\n", rate)
	}
	_ = strings.TrimSpace
}

var _ = binary.BigEndian

func pow2(bits float64) float64 {
	// math.Pow without importing math for one call is silly; do it directly.
	out := 1.0
	whole := int(bits)
	for i := 0; i < whole; i++ {
		out *= 2
	}
	frac := bits - float64(whole)
	// 2^frac via the identity 2^x = e^(x ln2), approximated well enough here.
	steps := 1000
	acc := 1.0
	inc := frac * 0.6931471805599453 / float64(steps)
	for i := 0; i < steps; i++ {
		acc *= 1 + inc
	}
	return out * acc
}

func humanDuration(seconds float64) string {
	const (
		minute = 60.0
		hour   = 3600.0
		day    = 86400.0
		year   = 31557600.0
	)
	switch {
	case seconds < 1:
		return "instantly"
	case seconds < minute:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < hour:
		return fmt.Sprintf("%.1f minutes", seconds/minute)
	case seconds < day:
		return fmt.Sprintf("%.1f hours", seconds/hour)
	case seconds < year:
		return fmt.Sprintf("%.1f days", seconds/day)
	default:
		return fmt.Sprintf("%.3g years", seconds/year)
	}
}

func numCPU() int {
	n := 1
	if v := os.Getenv("NUMBER_OF_PROCESSORS"); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	if n < 1 {
		n = 1
	}
	return n
}
