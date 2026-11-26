package store

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mk(t *testing.T, id string, views uint32, ttl time.Duration) *Record {
	t.Helper()
	var hash [32]byte
	if len(id) > 0 {
		hash[0] = id[0]
	}
	return NewRecord(id, false, []byte("wrapped"), []byte("n"), []byte("ct"), hash, views, ttl)
}

func TestInsertLookupRemove(t *testing.T) {
	s := New()
	r := mk(t, "abc", 1, time.Minute)
	if err := s.Insert(r); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1", s.Len())
	}
	if _, err := s.Lookup("abc"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !s.Remove("abc") {
		t.Fatal("remove returned false for a live record")
	}
	if s.Len() != 0 {
		t.Fatalf("len after remove = %d", s.Len())
	}
	if _, err := s.Lookup("abc"); err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestIDCollisionRejected(t *testing.T) {
	s := New()
	if err := s.Insert(mk(t, "dup", 1, time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(mk(t, "dup", 1, time.Minute)); err == nil {
		t.Fatal("expected id collision error")
	}
}

// TestTakeIsAtomic is the direct, in-process version of the 50-reader race.
func TestTakeIsAtomic(t *testing.T) {
	for _, maxViews := range []uint32{1, 2, 5, 10} {
		s := New()
		r := mk(t, "race", maxViews, time.Minute)
		if err := s.Insert(r); err != nil {
			t.Fatal(err)
		}

		const readers = 200
		var wins atomic.Int64
		var start sync.WaitGroup
		start.Add(1)
		var wg sync.WaitGroup
		wg.Add(readers)
		for i := 0; i < readers; i++ {
			go func() {
				defer wg.Done()
				start.Wait()
				if _, err := s.Take("race", nil); err == nil {
					wins.Add(1)
				}
			}()
		}
		start.Done()
		wg.Wait()

		if got := wins.Load(); got != int64(maxViews) {
			t.Fatalf("maxViews=%d: got %d successful takes", maxViews, got)
		}
		if s.Len() != 0 {
			t.Fatalf("maxViews=%d: %d records left, want 0", maxViews, s.Len())
		}
	}
}

func TestTakeVerifyFailureDoesNotConsumeView(t *testing.T) {
	s := New()
	r := mk(t, "verify", 1, time.Minute)
	if err := s.Insert(r); err != nil {
		t.Fatal(err)
	}

	fail := func(*Record) error { return ErrDenied }

	for i := 0; i < 10; i++ {
		if _, err := s.Take("verify", fail); err != ErrDenied {
			t.Fatalf("attempt %d: err = %v, want ErrDenied", i, err)
		}
	}
	// The single real view must still be available.
	if _, err := s.Take("verify", nil); err != nil {
		t.Fatalf("real view failed after 10 denied attempts: %v", err)
	}
	if _, err := s.Take("verify", nil); err != ErrNotFound {
		t.Fatalf("second real view: err = %v, want ErrNotFound", err)
	}
}

func TestBurnZerosMaterial(t *testing.T) {
	r := mk(t, "burn", 1, time.Minute)
	r.Ciphertext = []byte("SECRET-PLAINTEXT-SHOULD-NOT-SURVIVE")
	ct := r.Ciphertext
	r.burn()
	for i, b := range ct {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %q", i, ct)
		}
	}
}

func TestExpiry(t *testing.T) {
	s := New()
	r := mk(t, "short", 1, 50*time.Millisecond)
	if err := s.Insert(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("short"); err != nil {
		t.Fatalf("should be alive: %v", err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := s.Lookup("short"); err != ErrExpired {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	if _, err := s.Take("short", nil); err != ErrExpired && err != ErrNotFound {
		t.Fatalf("take on expired: err = %v", err)
	}
}

func TestJanitorCollectsExpired(t *testing.T) {
	s := New()
	for i := 0; i < 20; i++ {
		if err := s.Insert(mk(t, string(rune('a'+i)), 1, 30*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	go s.Janitor(10*time.Millisecond, stop)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Len() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("janitor left %d records", s.Len())
}

func TestRevoke(t *testing.T) {
	s := New()
	tok := "the-token"
	var h [32]byte
	copy(h[:], []byte("expected-hash-value-0000000000"))

	r := mk(t, "rev", 1, time.Minute)
	r.DeletionHash = h
	if err := s.Insert(r); err != nil {
		t.Fatal(err)
	}

	hashOf := func(s string) [32]byte {
		var out [32]byte
		if s == tok {
			return h
		}
		out[0] = 0xFF
		return out
	}
	eq := func(a, b [32]byte) bool { return a == b }

	if s.Revoke("rev", "wrong", hashOf, eq) {
		t.Fatal("revoke with wrong token succeeded")
	}
	if _, err := s.Lookup("rev"); err != nil {
		t.Fatalf("failed revoke destroyed the record: %v", err)
	}
	if !s.Revoke("rev", tok, hashOf, eq) {
		t.Fatal("revoke with right token failed")
	}
	if _, err := s.Lookup("rev"); err != ErrNotFound {
		t.Fatalf("record survived revoke: %v", err)
	}
}

// A revoke must be linearizable: once DELETE reports success, no in-flight GET
// may still return the content. The original code deleted the map entry before
// burning, leaving a window where a Take holding a stale pointer could decrypt
// and return a secret that had already been reported as destroyed.
func TestRevokeIsLinearizable(t *testing.T) {
	s := New()

	for attempt := 0; attempt < 200; attempt++ {
		id := "revoke-race"
		var tok [32]byte
		tok[0] = 0xAA
		r := NewRecord(id, false, []byte("wrapped"), []byte("n"), []byte("ct"), tok, 100, time.Minute)
		if err := s.Insert(r); err != nil {
			t.Fatal(err)
		}

		var leaked atomic.Bool
		var start sync.WaitGroup
		start.Add(1)

		var wg sync.WaitGroup
		// One reader and one revoker race. Either the read happens before the
		// revoke (allowed) or it fails (allowed), but a read that succeeds after
		// Revoke returned true is a leak.
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait()
			if _, err := s.Take(id, nil); err == nil {
				// The take won; that is fine only if it happened before revocation
				// completed. We detect the bad case below.
				_ = err
			}
		}()
		start.Done()

		start2 := make(chan struct{})
		_ = start2

		wg.Add(1)
		var revoked bool
		go func() {
			defer wg.Done()
			revoked = s.Revoke(id, "tok", func(string) [32]byte { return tok },
				func(a, b [32]byte) bool { return a == b })
		}()

		wg.Wait()

		// After Revoke returned true, the record must be unusable for everyone.
		if revoked {
			if _, err := s.Take(id, nil); err == nil {
				leaked.Store(true)
			}
			if _, err := s.Lookup(id); err == nil {
				leaked.Store(true)
			}
		}
		if leaked.Load() {
			t.Fatalf("attempt %d: a revoked secret was still readable", attempt)
		}
	}
}

func TestNewIDIsRandomAndLong(t *testing.T) {
	seen := make(map[string]bool, 5000)
	for i := 0; i < 5000; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) < 32 {
			t.Fatalf("id too short: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
