// Package audit writes structured JSON lines about who did what and when.
//
// Content, passphrase, raw secret id and deletion token are never arguments
// here. Callers pass an HMAC-derived id tag instead of the raw id.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event names are fixed constants so typos cannot silently create new events.
const (
	EvCreate      = "secret.create"
	EvView        = "secret.view"
	EvViewDenied  = "secret.view_denied"
	EvRevoke      = "secret.revoke"
	EvRevokeFail  = "secret.revoke_denied"
	EvExpired     = "secret.expired"
	EvRateLimited = "rate.limited"
)

// Entry is one audit record.
type Entry struct {
	Time   string `json:"ts"`
	Event  string `json:"event"`
	IDTag  string `json:"id_tag,omitempty"`
	IP     string `json:"ip,omitempty"`
	Status int    `json:"status,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Logger serializes entries to a writer as JSON lines.
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
	now func() time.Time
}

// New returns a logger writing to w.
func New(w io.Writer) *Logger {
	enc := json.NewEncoder(w)
	// The encoder escapes nothing dangerous for JSON-lines consumption, but we
	// keep it deterministic and compact for log shippers.
	return &Logger{w: w, enc: enc, now: time.Now}
}

// SetClock overrides the clock (tests only).
func (l *Logger) SetClock(f func() time.Time) { l.now = f }

// Log writes one entry. Errors are swallowed: an audit sink failure must never
// turn a successful request into a 500.
func (l *Logger) Log(e Entry) {
	if l == nil {
		return
	}
	e.Time = l.now().UTC().Format(time.RFC3339Nano)
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}
