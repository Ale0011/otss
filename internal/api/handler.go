package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ale0011/otss/internal/audit"
	"github.com/Ale0011/otss/internal/envelope"
	"github.com/Ale0011/otss/internal/metrics"
	"github.com/Ale0011/otss/internal/ratelimit"
	"github.com/Ale0011/otss/internal/store"
)

// Limits and defaults. Kept as named constants so tests and the design note
// cannot drift apart.
const (
	maxContentBytes = 64 << 10 // 64 KiB of secret material
	maxTTL          = 7 * 24 * 3600
	minTTL          = 1
	minViews        = 1
	maxViews        = 100
	maxPassphrase   = 1024
	maxBodyBytes    = maxContentBytes*2 + 4096
)

// Config is the runtime configuration of the service.
type Config struct {
	PublicBaseURL string
	TrustedProxy  string
	// MetricsToken, when non-empty, requires Authorization: Bearer <token>
	// (or X-Metrics-Token) to scrape /metrics. Empty means open — fine for
	// local challenge deployments, wrong for a public internet face.
	MetricsToken string
	CreateRate   float64
	CreateBurst  float64
	ReadRate     float64
	ReadBurst    float64
}

// Server holds every handler dependency.
type Server struct {
	cfg      Config
	sealer   *envelope.Sealer
	store    *store.Store
	audit    *audit.Logger
	metrics  *metrics.Registry
	ips      *ratelimit.ClientIPResolver
	createRL *ratelimit.Limiter
	readRL   *ratelimit.Limiter

	cCreate       *metrics.Counter
	cView         *metrics.Counter
	cViewDenied   *metrics.Counter
	cRevoke       *metrics.Counter
	cRevokeDenied *metrics.Counter
	cRateLimited  *metrics.Counter
	cBadRequest   *metrics.Counter
	cReqDur       *metrics.Histogram
}

// New wires a Server from its dependencies.
func New(cfg Config, sealer *envelope.Sealer, st *store.Store, au *audit.Logger, m *metrics.Registry) *Server {
	if cfg.CreateRate <= 0 {
		cfg.CreateRate, cfg.CreateBurst = 10, 20
	}
	if cfg.ReadRate <= 0 {
		cfg.ReadRate, cfg.ReadBurst = 50, 100
	}
	s := &Server{
		cfg:      cfg,
		sealer:   sealer,
		store:    st,
		audit:    au,
		metrics:  m,
		ips:      ratelimit.NewClientIPResolver(cfg.TrustedProxy),
		createRL: ratelimit.New(cfg.CreateRate, cfg.CreateBurst),
		readRL:   ratelimit.New(cfg.ReadRate, cfg.ReadBurst),
	}
	s.cCreate = m.Counter("otss_secrets_created_total", "Secrets created")
	s.cView = m.Counter("otss_secret_views_total", "Successful secret views")
	s.cViewDenied = m.Counter("otss_secret_view_denied_total", "Rejected view attempts")
	s.cRevoke = m.Counter("otss_secret_revoked_total", "Secrets revoked by their creator")
	s.cRevokeDenied = m.Counter("otss_secret_revoke_denied_total", "Rejected revoke attempts")
	s.cRateLimited = m.Counter("otss_rate_limited_total", "Requests rejected by the rate limiter")
	s.cBadRequest = m.Counter("otss_bad_requests_total", "Malformed requests")
	s.cReqDur = m.Histogram("otss_request_duration_seconds", "Request latency")
	m.Gauge("otss_secrets_live", "Secrets currently held in memory", st.Len)
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/secrets", s.handleCreate)
	mux.HandleFunc("/secrets/form", s.handleCreateForm)
	mux.HandleFunc("/s/", s.handleSecretPath)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/", s.handleIndex)
	return s.recoverPanic(s.securityHeaders(s.observe(mux)))
}

// --- middleware ---

func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.cReqDur.Observe(time.Since(start).Seconds())
	})
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Never echo the panic value: it could contain secret material.
				writeError(w, http.StatusInternalServerError, "internal")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders applies defensive response headers on every route.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private, max-age=0")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "0")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()")
		// Base CSP for every response, including JSON ones: a browser that is
		// tricked into navigating to an API path still gets nothing executable.
		// HTML pages override this with a policy that allows their stylesheet.
		h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// --- health & metrics ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if s.cfg.MetricsToken != "" && !metricsAuthorized(r, s.cfg.MetricsToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = s.metrics.WriteTo(w)
}

func metricsAuthorized(r *http.Request, want string) bool {
	if v := r.Header.Get("X-Metrics-Token"); subtle.ConstantTimeCompare([]byte(v), []byte(want)) == 1 {
		return true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		got := auth[len(prefix):]
		return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
	}
	return false
}

// --- create ---

type createRequest struct {
	Content    *string `json:"content"`
	TTLSeconds *int    `json:"ttl_seconds"`
	MaxViews   *int    `json:"max_views"`
	Passphrase *string `json:"passphrase"`
}

type createResponse struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	DeletionToken string `json:"deletion_token"`
	ExpiresAt     string `json:"expires_at"`
	MaxViews      int    `json:"max_views"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	ip := s.ips.ClientIP(r)
	if !s.limit(s.createRL, "c:"+ip, ip, "create", w) {
		return
	}

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req createRequest
	if err := dec.Decode(&req); err != nil {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if dec.More() {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if req.Content == nil || len(*req.Content) == 0 {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "missing_content")
		return
	}
	if len(*req.Content) > maxContentBytes {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "content_too_large")
		return
	}

	ttl := 86400
	if req.TTLSeconds != nil {
		ttl = *req.TTLSeconds
	}
	if ttl < minTTL || ttl > maxTTL {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "invalid_ttl")
		return
	}

	views := 1
	if req.MaxViews != nil {
		views = *req.MaxViews
	}
	if views < minViews || views > maxViews {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "invalid_max_views")
		return
	}

	passphrase := ""
	if req.Passphrase != nil {
		passphrase = *req.Passphrase
	}
	if len(passphrase) > maxPassphrase {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "passphrase_too_long")
		return
	}

	id, err := store.NewID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	deletionToken, err := store.NewDeletionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	plaintext := []byte(*req.Content)
	wrapped, nonce, ct, err := s.sealer.Seal(id, passphrase, plaintext)
	envelope.Zero(plaintext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	rec := store.NewRecord(
		id,
		passphrase != "",
		wrapped, nonce, ct,
		envelope.DeletionHash(deletionToken),
		uint32(views),
		time.Duration(ttl)*time.Second,
	)
	if err := s.store.Insert(rec); err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	// The delete token is returned exactly once, in this response, and never
	// logged. The same goes for the passphrase, which stays in the fragment.
	s.cCreate.Inc("")
	s.audit.Log(audit.Entry{
		Event: audit.EvCreate,
		IDTag: s.sealer.IDTag(id),
		IP:    ip,
		Note:  "max_views=" + strconv.Itoa(views) + " ttl=" + strconv.Itoa(ttl),
	})

	base := s.shareBase(r)
	shareURL := base + "/s/" + id
	if passphrase != "" {
		shareURL += "#p=" + base64.RawURLEncoding.EncodeToString([]byte(passphrase))
	}

	writeJSON(w, http.StatusCreated, createResponse{
		ID:            id,
		URL:           shareURL,
		DeletionToken: deletionToken,
		ExpiresAt:     rec.CreatedAt().Add(time.Duration(ttl) * time.Second).UTC().Format(time.RFC3339),
		MaxViews:      views,
	})
}

// shareBase builds the origin used in share URLs. PUBLIC_BASE_URL wins;
// otherwise only loopback Host values are accepted.
func (s *Server) shareBase(r *http.Request) string {
	if b := strings.TrimRight(s.cfg.PublicBaseURL, "/"); b != "" {
		return b
	}

	host := r.Host
	if !isLoopbackHost(host) {
		host = "localhost"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + host
}

// isLoopbackHost accepts only loopback hostnames / IPs, with an optional port.
func isLoopbackHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	host := h
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
		// host:port (IPv4 or name). IPv6 bracket form handled below.
		host = h[:i]
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	return false
}

// --- routing for /s/ ---

func (s *Server) handleSecretPath(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/s/")

	if id, ok := strings.CutSuffix(rest, "/open"); ok {
		if id != "" && !strings.Contains(id, "/") {
			s.handleOpen(w, r, id)
			return
		}
		writeError(w, http.StatusNotFound, "not_found")
		return
	}

	if rest == "" || strings.Contains(rest, "/") {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}

	switch r.Method {
	case http.MethodDelete:
		s.handleDelete(w, r, rest)
	case http.MethodGet:
		s.handleGet(w, r, rest)
	case http.MethodHead:
		// HEAD is safe (RFC 9110) and must not consume a view. Answer with a
		// flat 405 rather than GET-equivalent headers.
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "head_not_supported")
	case http.MethodPost:
		// The unlock form posts back to its own URL, so a plain POST to the
		// secret path is the passphrase submission. /open stays as an explicit
		// alias for API clients that prefer a distinct route.
		s.handleOpen(w, r, rest)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
	}
}

// --- read ---

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	ip := s.ips.ClientIP(r)
	if !s.limit(s.readRL, "r:"+ip, ip, "read", w) {
		return
	}

	passphrase := passphraseFromRequest(r)

	rec, err := s.store.Lookup(id)
	if err != nil {
		s.rejectView(w, r, ip, id, passphrase, false)
		return
	}

	if rec.HasPassphrase && passphrase == "" {
		// Needs a passphrase: same response shape as a missing id.
		//
		// Browsers get the unlock form because they need a way to type the
		// passphrase, and they get the same page for nonexistent ids above.
		if !isBrowser(r) {
			s.rejectView(w, r, ip, id, passphrase, false)
			return
		}
		s.renderUnlockPage(w, r, id, "")
		return
	}

	s.deliver(w, r, id, ip, passphrase)
}

// handleOpen accepts a passphrase in a request body so browsers never put it in
// a URL that could leak through history, referrers or proxy logs. JSON (API) and
// application/x-www-form-urlencoded (the unlock form) are accepted. Multipart
// is deliberately refused: ParseForm does not parse it, and supporting it would
// reopen a "silent empty passphrase" footgun.
func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	ip := s.ips.ClientIP(r)
	if !s.limit(s.readRL, "r:"+ip, ip, "read", w) {
		return
	}

	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var passphrase string
	switch mt {
	case "application/x-www-form-urlencoded":
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if err := r.ParseForm(); err != nil {
			s.cBadRequest.Inc("")
			if isBrowser(r) {
				s.renderGenericPage(w, http.StatusBadRequest, "Bad request", "The form could not be read.")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid_form")
			return
		}
		passphrase = r.PostForm.Get("passphrase")
	case "application/json", "":
		// Empty Content-Type tolerated for JSON clients; create is stricter.
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		var body struct {
			Passphrase string `json:"passphrase"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			s.cBadRequest.Inc("")
			writeError(w, http.StatusBadRequest, "invalid_json")
			return
		}
		passphrase = body.Passphrase
	default:
		s.cBadRequest.Inc("")
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}

	if len(passphrase) > maxPassphrase {
		s.cBadRequest.Inc("")
		writeError(w, http.StatusBadRequest, "passphrase_too_long")
		return
	}

	s.deliver(w, r, id, ip, passphrase)
}

// deliver performs the atomic take and renders the result.
func (s *Server) deliver(w http.ResponseWriter, r *http.Request, id, ip, passphrase string) {
	var plain []byte
	// verifyRan records whether the decryption was actually attempted, so the
	// rejection path can match the work done instead of doing it twice.
	verifyRan := false
	taken, err := s.store.Take(id, func(rc *store.Record) error {
		verifyRan = true
		var oerr error
		plain, oerr = s.sealer.Open(id, passphrase, rc.WrappedDEK, rc.Nonce, rc.Ciphertext)
		return oerr
	})
	if err != nil {
		s.rejectView(w, r, ip, id, passphrase, verifyRan)
		return
	}
	defer envelope.Zero(plain)

	s.cView.Inc("")
	s.audit.Log(audit.Entry{
		Event:  audit.EvView,
		IDTag:  s.sealer.IDTag(id),
		IP:     ip,
		Status: http.StatusOK,
		Note:   "remaining=" + strconv.FormatUint(uint64(taken.Remaining()), 10),
	})

	if isBrowser(r) {
		s.renderSecretPage(w, plain, taken.Remaining())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              id,
		"content":         string(plain),
		"views_remaining": taken.Remaining(),
	})
}

// rejectView answers every failing read identically.
//
// Not-found, expired and wrong-passphrase all produce the same status and the
// same body. On top of that, every path performs exactly one AEAD decryption:
//
//   - a wrong passphrase already paid for one real Open inside Take, so didWork
//     is true and no decoy is burned;
//   - a missing or expired id paid for nothing, so doWork runs a decoy Open on
//     random bytes to match.
//
// Equal status, equal body, equal crypto: neither the response nor the latency
// tells an attacker whether an id exists.
func (s *Server) rejectView(w http.ResponseWriter, r *http.Request, ip, id, passphrase string, didWork bool) {
	s.cViewDenied.Inc("")
	if !didWork {
		s.doWork(id, passphrase)
	}
	s.audit.Log(audit.Entry{
		Event:  audit.EvViewDenied,
		IDTag:  s.sealer.IDTag(id),
		IP:     ip,
		Status: http.StatusNotFound,
	})
	if isBrowser(r) {
		s.renderUnlockPage(w, r, id, "")
		return
	}
	writeError(w, http.StatusNotFound, "not_found")
}

// doWork mirrors the cost of a real Open on synthetic ciphertext.
func (s *Server) doWork(id, passphrase string) {
	wrapped := make([]byte, 12+32+16)
	nonce := make([]byte, 12)
	ct := make([]byte, 32)
	if _, err := rand.Read(wrapped); err != nil {
		return
	}
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if _, err := rand.Read(ct); err != nil {
		return
	}
	_, _ = s.sealer.Open(id, passphrase, wrapped, nonce, ct)
}

// --- revoke ---

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	ip := s.ips.ClientIP(r)
	if !s.limit(s.readRL, "r:"+ip, ip, "revoke", w) {
		return
	}

	// Token from header or JSON body only — never from the query string.
	token := r.Header.Get("X-Deletion-Token")
	if token == "" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var body struct {
			DeletionToken string `json:"deletion_token"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err == nil {
			token = body.DeletionToken
		}
	}

	ok := s.store.Revoke(id, token, envelope.DeletionHash, envelope.DeletionHashEqual)
	if !ok {
		s.cRevokeDenied.Inc("")
		s.audit.Log(audit.Entry{
			Event:  audit.EvRevokeFail,
			IDTag:  s.sealer.IDTag(id),
			IP:     ip,
			Status: http.StatusNotFound,
		})
		writeError(w, http.StatusNotFound, "not_found")
		return
	}

	s.cRevoke.Inc("")
	s.audit.Log(audit.Entry{
		Event:  audit.EvRevoke,
		IDTag:  s.sealer.IDTag(id),
		IP:     ip,
		Status: http.StatusNoContent,
	})
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func (s *Server) limit(l *ratelimit.Limiter, key, ip, kind string, w http.ResponseWriter) bool {
	ok, wait := l.Allow(key)
	if ok {
		return true
	}
	s.cRateLimited.Inc("")
	s.audit.Log(audit.Entry{Event: audit.EvRateLimited, IP: ip, Note: kind})
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	writeError(w, http.StatusTooManyRequests, "rate_limited")
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func passphraseFromRequest(r *http.Request) string {
	if v := r.Header.Get("X-Passphrase"); v != "" {
		return v
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	// A passphrase is deliberately NOT accepted from the query string.
	//
	// It would land in proxy access logs, browser history and Referer headers —
	// the exact places the #p= fragment design exists to avoid. Deletion tokens
	// are refused from query strings for the same reason; the passphrase is the
	// more sensitive credential of the two, so it gets the same treatment.
	//
	// Clients that cannot set headers (a browser form) use POST /s/{id} with the
	// passphrase in the body.
	return ""
}

func isBrowser(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// timeSeconds converts an int to a Duration in seconds.
func timeSeconds(n int) time.Duration { return time.Duration(n) * time.Second }
