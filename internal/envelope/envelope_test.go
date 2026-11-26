package envelope

import (
	"bytes"
	"testing"
	"time"
)

func newSealer(t *testing.T) *Sealer {
	t.Helper()
	k, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := newSealer(t)
	const id, pass = "someid", "somepass"
	plain := []byte("hello, world")

	wrapped, nonce, ct, err := s.Seal(id, pass, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(id, pass, wrapped, nonce, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestRoundTripWithoutPassphrase(t *testing.T) {
	s := newSealer(t)
	wrapped, nonce, ct, err := s.Seal("id2", "", []byte("no pass"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open("id2", "", wrapped, nonce, ct); err != nil {
		t.Fatalf("open: %v", err)
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	s := newSealer(t)
	wrapped, nonce, ct, err := s.Seal("id3", "right", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open("id3", "wrong", wrapped, nonce, ct); err != ErrAuth {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
}

// The secret id is bound as AAD, so moving a blob to another id must fail. This
// is what stops a "swap two ciphertexts" attack against a dump.
func TestIDIsBoundToCiphertext(t *testing.T) {
	s := newSealer(t)
	wrapped, nonce, ct, err := s.Seal("idA", "p", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open("idB", "p", wrapped, nonce, ct); err != ErrAuth {
		t.Fatal("ciphertext decrypted under a different id")
	}
}

func TestTamperDetection(t *testing.T) {
	s := newSealer(t)
	wrapped, nonce, ct, err := s.Seal("id4", "p", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	flip := func(b []byte) []byte {
		out := append([]byte(nil), b...)
		out[len(out)-1] ^= 0xFF
		return out
	}

	if _, err := s.Open("id4", "p", flip(wrapped), nonce, ct); err != ErrAuth {
		t.Error("tampered wrapped key was accepted")
	}
	if _, err := s.Open("id4", "p", wrapped, flip(nonce), ct); err != ErrAuth {
		t.Error("tampered nonce was accepted")
	}
	if _, err := s.Open("id4", "p", wrapped, nonce, flip(ct)); err != ErrAuth {
		t.Error("tampered ciphertext was accepted")
	}
}

func TestShortAndEmptyInputs(t *testing.T) {
	s := newSealer(t)
	cases := []struct {
		w, n, c []byte
	}{
		{nil, nil, nil},
		{[]byte("short"), []byte("n"), []byte("ct")},
		{make([]byte, 60), make([]byte, 4), make([]byte, 40)},
		{make([]byte, 60), make([]byte, 12), make([]byte, 4)},
	}
	for i, tc := range cases {
		if _, err := s.Open("x", "", tc.w, tc.n, tc.c); err != ErrAuth {
			t.Errorf("case %d: err = %v, want ErrAuth", i, err)
		}
	}
}

func TestDifferentMasterKeysCannotOpen(t *testing.T) {
	a := newSealer(t)
	b := newSealer(t)

	wrapped, nonce, ct, err := a.Seal("id5", "", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open("id5", "", wrapped, nonce, ct); err != ErrAuth {
		t.Fatal("a different master key decrypted the blob")
	}
}

func TestNonceIsFreshPerSeal(t *testing.T) {
	s := newSealer(t)
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		_, nonce, _, err := s.Seal("same-id", "", []byte("identical plaintext"))
		if err != nil {
			t.Fatal(err)
		}
		k := string(nonce)
		if seen[k] {
			t.Fatal("nonce reuse detected")
		}
		seen[k] = true
	}
}

func TestMasterKeyLengthEnforced(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err != ErrMasterKey {
			t.Errorf("len %d: err = %v, want ErrMasterKey", n, err)
		}
	}
	if _, err := New(make([]byte, 32)); err != nil {
		t.Errorf("len 32 rejected: %v", err)
	}
}

func TestDeletionHash(t *testing.T) {
	a := DeletionHash("token-a")
	b := DeletionHash("token-b")
	if DeletionHashEqual(a, b) {
		t.Fatal("different tokens hashed equal")
	}
	if !DeletionHashEqual(a, DeletionHash("token-a")) {
		t.Fatal("same token hashed differently")
	}
}

func TestIDTagIsStableAndOpaque(t *testing.T) {
	s := newSealer(t)
	t1 := s.IDTag("secret-id-123")
	t2 := s.IDTag("secret-id-123")
	if t1 != t2 {
		t.Fatal("IDTag is not deterministic")
	}
	if t1 == "secret-id-123" || len(t1) != 8 {
		t.Fatalf("IDTag looks wrong: %q", t1)
	}
	if s.IDTag("secret-id-124") == t1 {
		t.Fatal("IDTag collided for adjacent ids")
	}
}

// TestPassphraseKDFIsExpensive is a guard rail, not a microbenchmark.
//
// The first version of this service used a single HMAC-SHA256 as the KDF, which
// let an attacker with a memory dump try ~1.3M passphrases a second. If someone
// ever "optimizes" the derivation back to something cheap, this test fails and
// points them at the reasoning in DESIGN.md.
func TestPassphraseKDFIsExpensive(t *testing.T) {
	if pbkdf2Iterations < 200000 {
		t.Fatalf("pbkdf2Iterations is %d; the offline-attack math in DESIGN.md assumes >= 200000",
			pbkdf2Iterations)
	}

	s := newSealer(t)

	// One derivation must cost clearly more than one raw AEAD operation. On any
	// hardware this is a ~1000x separation, so the threshold is not flaky.
	start := time.Now()
	if _, _, _, err := s.Seal("timing-id", "a-passphrase", []byte("x")); err != nil {
		t.Fatal(err)
	}
	withPass := time.Since(start)

	start = time.Now()
	if _, _, _, err := s.Seal("timing-id", "", []byte("x")); err != nil {
		t.Fatal(err)
	}
	withoutPass := time.Since(start)

	if withPass < 10*time.Millisecond {
		t.Fatalf("a passphrase seal took %v; the KDF is not stretched enough", withPass)
	}
	if withPass < 20*withoutPass {
		t.Fatalf("passphrase seal %v is not meaningfully slower than plain seal %v",
			withPass, withoutPass)
	}
}

// An empty passphrase must select the cheap path, otherwise every unprotected
// secret pays 40ms and the load test collapses to single-digit rps.
func TestEmptyPassphraseUsesCheapPath(t *testing.T) {
	s := newSealer(t)
	start := time.Now()
	for i := 0; i < 20; i++ {
		if _, _, _, err := s.Seal("cheap-id", "", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("20 unprotected seals took %v; the cheap path is not being taken", elapsed)
	}
}
