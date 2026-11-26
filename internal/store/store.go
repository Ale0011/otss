// Package store holds secrets in memory only.
//
// There is no database and no volume. The only thing that would ever reach disk
// is ciphertext, and we choose not to persist it at all: a restart drops
// everything. That removes an entire attack class (backups, soft deletes,
// "undelete it after the victim read it") and satisfies "no plaintext at rest"
// by construction, not by policy.
//
// View-once is enforced inside a single per-secret critical section, so N
// concurrent readers can never both win, regardless of scheduling.
package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrExpired  = errors.New("store: expired")
	ErrDenied   = errors.New("store: authentication failed")
)

// Record is one stored secret. Plaintext never lives here: only sealed bytes.
type Record struct {
	ID string

	// HasPassphrase is true when the creator supplied one.
	HasPassphrase bool

	WrappedDEK []byte
	Nonce      []byte
	Ciphertext []byte

	// DeletionHash authenticates DELETE; the raw token is never stored.
	DeletionHash [32]byte

	createdAt time.Time
	expiresAt time.Time // zero = no TTL

	mu             sync.Mutex
	viewsRemaining uint32
	// burned is set once the record has been destroyed, so a stale pointer held
	// by an in-flight goroutine cannot resurrect it.
	burned atomic.Bool
}

// Remaining reports views left. Exposed for tests and metrics only.
func (r *Record) Remaining() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.viewsRemaining
}

// Expired reports whether the TTL has elapsed.
func (r *Record) Expired(now time.Time) bool {
	if r.expiresAt.IsZero() {
		return false
	}
	return !now.Before(r.expiresAt)
}

// burn irreversibly destroys the sealed material. Returns false if already dead.
func (r *Record) burn() bool {
	if r.burned.Swap(true) {
		return false
	}
	for i := range r.Ciphertext {
		r.Ciphertext[i] = 0
	}
	for i := range r.WrappedDEK {
		r.WrappedDEK[i] = 0
	}
	for i := range r.Nonce {
		r.Nonce[i] = 0
	}
	for i := range r.DeletionHash {
		r.DeletionHash[i] = 0
	}
	return true
}

const shardCount = 512

type shard struct {
	mu sync.RWMutex
	m  map[string]*Record
}

// Store is a sharded in-memory map of live secrets.
type Store struct {
	shards [shardCount]*shard

	live    atomic.Int64
	pending atomic.Int64 // records with a TTL, for the janitor
}

// New returns an empty store.
func New() *Store {
	s := &Store{}
	for i := range s.shards {
		s.shards[i] = &shard{m: make(map[string]*Record)}
	}
	return s
}

func shardIndex(id string) int {
	var h uint32 = 2166136261 // FNV-1a; ids are uniform so this spreads evenly
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	return int(h & (shardCount - 1))
}

// NewID returns a 192-bit random, URL-safe, non-sequential identifier.
func NewID() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// NewDeletionToken returns a 256-bit random revocation token.
func NewDeletionToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// NewRecord builds a record from sealed material. ttl<=0 means no expiry.
func NewRecord(id string, hasPassphrase bool, wrappedDEK, nonce, ciphertext []byte, delHash [32]byte, maxViews uint32, ttl time.Duration) *Record {
	now := time.Now()
	r := &Record{
		ID:             id,
		HasPassphrase:  hasPassphrase,
		WrappedDEK:     wrappedDEK,
		Nonce:          nonce,
		Ciphertext:     ciphertext,
		DeletionHash:   delHash,
		createdAt:      now,
		viewsRemaining: maxViews,
	}
	if ttl > 0 {
		r.expiresAt = now.Add(ttl)
	}
	return r
}

// Insert adds a record, failing on id collision.
func (s *Store) Insert(r *Record) error {
	sh := s.shards[shardIndex(r.ID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.m[r.ID]; ok {
		return errors.New("store: id collision")
	}
	sh.m[r.ID] = r
	s.live.Add(1)
	if !r.expiresAt.IsZero() {
		s.pending.Add(1)
	}
	return nil
}

// Lookup returns the record without consuming a view. Used by DELETE and by the
// GET path to decide how to answer before it commits.
func (s *Store) Lookup(id string) (*Record, error) {
	sh := s.shards[shardIndex(id)]
	sh.mu.RLock()
	r, ok := sh.m[id]
	sh.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if r.Expired(time.Now()) {
		s.Remove(id)
		return nil, ErrExpired
	}
	return r, nil
}

// verifyFunc is called with the record's sealed material while the record lock
// is held. Returning an error aborts the take without consuming a view.
type verifyFunc func(r *Record) error

// Take atomically verifies and consumes one view.
//
// Order matters: the passphrase is checked *before* the counter is decremented,
// so an attacker who has the link but not the passphrase cannot burn the
// recipient's only view. Decrement and removal happen in the same critical
// section, so exactly max_views callers can ever succeed.
func (s *Store) Take(id string, verify verifyFunc) (*Record, error) {
	sh := s.shards[shardIndex(id)]

	sh.mu.RLock()
	r, ok := sh.m[id]
	sh.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}

	r.mu.Lock()

	if r.burned.Load() {
		r.mu.Unlock()
		return nil, ErrNotFound
	}
	if r.Expired(time.Now()) {
		r.mu.Unlock()
		s.Remove(id)
		return nil, ErrExpired
	}
	if r.viewsRemaining == 0 {
		r.mu.Unlock()
		s.Remove(id)
		return nil, ErrNotFound
	}

	if verify != nil {
		if err := verify(r); err != nil {
			// Authentication failure: no view consumed. Rate limiting, not
			// destructive behaviour, is what stops brute force.
			r.mu.Unlock()
			return nil, ErrDenied
		}
	}

	r.viewsRemaining--
	last := r.viewsRemaining == 0

	if last {
		// Burn while still holding r.mu: a concurrent Take blocked on r.mu will
		// observe burned==true, and a reader already inside verify() cannot be
		// racing with burn zeroing the bytes it is decrypting.
		r.burn()
	}
	r.mu.Unlock()

	if last {
		// Drop the map entry last, and only if it is still this exact record.
		// Lock order here is Record.mu then shard.mu, matching removeRecord, so
		// there is no cycle with the paths that take them in that order.
		s.dropFromMap(r)
	}

	return r, nil
}

// dropFromMap removes r from its shard if, and only if, the entry still points
// at r. Pointer identity prevents deleting a different record that reused the id.
func (s *Store) dropFromMap(r *Record) {
	sh := s.shards[shardIndex(r.ID)]
	sh.mu.Lock()
	if cur, ok := sh.m[r.ID]; ok && cur == r {
		delete(sh.m, r.ID)
		s.live.Add(-1)
		if !r.expiresAt.IsZero() {
			s.pending.Add(-1)
		}
	}
	sh.mu.Unlock()
}

// Remove burns and deletes a record. Returns true if this call destroyed it.
//
// Lock order is always Record.mu before shard.mu. Burning first makes revocation
// linearizable: a Take that grabs Record.mu before this call legitimately reads
// before the delete; a Take that grabs it after sees burned and fails. Burning
// after the map deletion instead left a window where a stale pointer could still
// return content for a secret that DELETE had already reported as gone.
func (s *Store) Remove(id string) bool {
	sh := s.shards[shardIndex(id)]

	sh.mu.RLock()
	r, ok := sh.m[id]
	sh.mu.RUnlock()
	if !ok {
		return false
	}
	return s.removeRecord(r)
}

// removeRecord deletes exactly the given record, verifying pointer identity under
// the shard lock so it can never remove a different record that happens to share
// the id. Lock order is Record.mu then shard.mu, consistently.
func (s *Store) removeRecord(r *Record) bool {
	r.mu.Lock()
	burned := r.burn()
	r.mu.Unlock()

	// Even if another path already burned it, make sure the map entry is gone and
	// the counters are right. The pointer check keeps this from deleting a
	// replacement that happens to share the id.
	sh := s.shards[shardIndex(r.ID)]
	sh.mu.Lock()
	if cur, ok := sh.m[r.ID]; ok && cur == r {
		delete(sh.m, r.ID)
		s.live.Add(-1)
		if !r.expiresAt.IsZero() {
			s.pending.Add(-1)
		}
	}
	sh.mu.Unlock()

	return burned
}

// Revoke deletes a record if the supplied token matches. Both the "no such id"
// and "wrong token" cases return false and are indistinguishable to callers.
//
// The deletion is bound to the exact record that was validated, not to the id:
// comparing the token and then calling Remove(id) would be a time-of-check to
// time-of-use bug if a record were ever removed and another inserted under the
// same id in between. Ids are 192-bit random so that cannot happen today, but
// the store should not depend on the id generator staying that way.
func (s *Store) Revoke(id string, token string, hash func(string) [32]byte, equal func(a, b [32]byte) bool) bool {
	sh := s.shards[shardIndex(id)]

	sh.mu.RLock()
	r, ok := sh.m[id]
	sh.mu.RUnlock()
	if !ok {
		return false
	}

	r.mu.Lock()
	if r.burned.Load() {
		r.mu.Unlock()
		return false
	}
	want := r.DeletionHash
	r.mu.Unlock()

	if !equal(hash(token), want) {
		return false
	}

	return s.removeRecord(r)
}

// Len reports the number of live secrets.
func (s *Store) Len() int64 { return s.live.Load() }

// Janitor collects expired records until stop is closed. Cheap when idle: with
// no TTL'd records it does nothing at all.
func (s *Store) Janitor(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			if s.pending.Load() == 0 {
				continue
			}
			for i := range s.shards {
				sh := s.shards[i]
				var expired []string
				sh.mu.RLock()
				for id, r := range sh.m {
					if r.Expired(now) {
						expired = append(expired, id)
					}
				}
				sh.mu.RUnlock()
				for _, id := range expired {
					s.Remove(id)
				}
			}
		}
	}
}

// CreatedAt exposes creation time for tests.
func (r *Record) CreatedAt() time.Time { return r.createdAt }
