// Package envelope implements the at-rest crypto for a one-time secret.
//
// Model: every secret gets a fresh 256-bit data key (DEK). The content is sealed
// with AES-256-GCM under that DEK. The DEK itself is wrapped with a key that is
// derived from (master key, secret id, passphrase). That means:
//
//   - the secret id and the passphrase are *key material*, not just an index;
//   - a memory/heap dump that captures only the ciphertext is useless;
//   - a wrong passphrase is not merely "rejected", it derives a different
//     wrapping key, so unwrapping fails inside GCM (constant-time tag check);
//   - swapping a blob from one id to another fails, because the id is bound in
//     as additional authenticated data on both layers.
//
// Nothing in this package ever logs or retains plaintext or key material.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

var (
	// ErrAuth is returned for every authentication failure: bad passphrase,
	// tampered blob, wrong id. Callers must not distinguish between them.
	ErrAuth = errors.New("envelope: authentication failed")
	// ErrMasterKey is returned when the master key is not 32 bytes.
	ErrMasterKey = errors.New("envelope: master key must be 32 bytes")
)

const (
	// MasterKeyLen is the required master key length in bytes.
	MasterKeyLen = 32
	// DEKLen is the per-secret data key length in bytes.
	DEKLen = 32

	nonceLen = 12 // standard GCM nonce
	tagLen   = 16 // GCM tag
)

// Sealer holds the in-memory master key.
type Sealer struct {
	master [MasterKeyLen]byte
}

// GenerateMasterKey returns 32 fresh random bytes.
func GenerateMasterKey() ([]byte, error) {
	k := make([]byte, MasterKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// New builds a Sealer from a 32-byte master key.
func New(master []byte) (*Sealer, error) {
	if len(master) != MasterKeyLen {
		return nil, ErrMasterKey
	}
	s := &Sealer{}
	copy(s.master[:], master)
	return s, nil
}

// Zero overwrites b with zeroes. Used to shorten the lifetime of key material
// and decrypted content in the heap.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func aad(secretID string) []byte {
	b := make([]byte, 0, 10+len(secretID))
	b = append(b, "otss:v1:ad\x00"...)
	b = append(b, secretID...)
	return b
}

// wrapKey derives the DEK-wrapping key from master, id and passphrase.
// Passphrase-protected secrets use PBKDF2; empty passphrase uses a cheap HMAC.
func (s *Sealer) wrapKey(secretID, passphrase string) []byte {
	salt := hmac.New(sha256.New, s.master[:])
	salt.Write([]byte("otss:v2:wrap-salt\x00"))
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(secretID)))
	salt.Write(lb[:])
	salt.Write([]byte(secretID))
	saltSum := salt.Sum(nil)

	if passphrase == "" {
		// Unprotected secret: bind the master key and id, no stretching needed.
		m := hmac.New(sha256.New, s.master[:])
		m.Write([]byte("otss:v2:wrap-key-plain\x00"))
		m.Write(saltSum)
		return m.Sum(nil)
	}

	deriveSem <- struct{}{}
	defer func() { <-deriveSem }()
	return pbkdf2SHA256([]byte(passphrase), saltSum, pbkdf2Iterations, 32, s.master[:])
}

const pbkdf2Iterations = 300000

// deriveSem bounds concurrent PBKDF2 derivations under load.
var deriveSem = make(chan struct{}, maxParallelDerivations)

const maxParallelDerivations = 32

// pbkdf2SHA256 implements PBKDF2 (RFC 8018) with HMAC-SHA256.
//
// It is written out rather than imported so the whole service stays
// dependency-free, and it is deliberately small enough to audit by eye. The
// mixingKey parameter is a local extension: it is used as the HMAC key, so the
// master key is required to evaluate a guess at all.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int, mixingKey []byte) []byte {
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

		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
		Zero(u)
		Zero(t)
	}
	return out[:keyLen]
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Seal encrypts plaintext for secretID under a fresh DEK.
// It returns the wrapped DEK (nonce||ciphertext), the content nonce and the
// content ciphertext (which already includes the GCM tag).
func (s *Sealer) Seal(secretID, passphrase string, plaintext []byte) (wrappedDEK, nonce, ciphertext []byte, err error) {
	dek := make([]byte, DEKLen)
	if _, err = rand.Read(dek); err != nil {
		return nil, nil, nil, err
	}
	defer Zero(dek)

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, nonceLen)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad(secretID))

	wk := s.wrapKey(secretID, passphrase)
	defer Zero(wk)
	wgcm, err := newGCM(wk)
	if err != nil {
		return nil, nil, nil, err
	}
	wn := make([]byte, nonceLen)
	if _, err = rand.Read(wn); err != nil {
		return nil, nil, nil, err
	}
	wct := wgcm.Seal(nil, wn, dek, aad(secretID))

	wrappedDEK = make([]byte, 0, len(wn)+len(wct))
	wrappedDEK = append(wrappedDEK, wn...)
	wrappedDEK = append(wrappedDEK, wct...)
	return wrappedDEK, nonce, ciphertext, nil
}

// Open decrypts a sealed secret. Every failure mode collapses into ErrAuth.
func (s *Sealer) Open(secretID, passphrase string, wrappedDEK, nonce, ciphertext []byte) ([]byte, error) {
	if len(wrappedDEK) < nonceLen+tagLen || len(nonce) != nonceLen || len(ciphertext) < tagLen {
		return nil, ErrAuth
	}
	wk := s.wrapKey(secretID, passphrase)
	defer Zero(wk)

	wgcm, err := newGCM(wk)
	if err != nil {
		return nil, ErrAuth
	}
	dek, err := wgcm.Open(nil, wrappedDEK[:nonceLen], wrappedDEK[nonceLen:], aad(secretID))
	if err != nil {
		return nil, ErrAuth
	}
	defer Zero(dek)

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, ErrAuth
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, aad(secretID))
	if err != nil {
		return nil, ErrAuth
	}
	return plain, nil
}

// DeletionHash is what we store for a revocation token: a one-way digest.
// A dump of live state cannot be turned back into a usable deletion token.
func DeletionHash(token string) [32]byte {
	h := sha256.New()
	h.Write([]byte("otss:v1:del-token\x00"))
	h.Write([]byte(token))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// DeletionHashEqual compares two deletion hashes in constant time.
func DeletionHashEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// IDTag returns a short, non-reversible tag for a secret id, for audit logs.
// Logging the raw id would let anyone holding the logs replay the share URL.
func (s *Sealer) IDTag(secretID string) string {
	m := hmac.New(sha256.New, s.master[:])
	m.Write([]byte("otss:v1:audit-id\x00"))
	m.Write([]byte(secretID))
	sum := m.Sum(nil)
	return hex.EncodeToString(sum[:4])
}
