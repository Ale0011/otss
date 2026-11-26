package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ale0011/otss/internal/api"
	"github.com/Ale0011/otss/internal/audit"
	"github.com/Ale0011/otss/internal/envelope"
	"github.com/Ale0011/otss/internal/metrics"
	"github.com/Ale0011/otss/internal/store"
)

// harness is a running server with generous rate limits so tests exercise logic
// rather than the limiter.
type harness struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	logs   *syncBuffer
	api    *api.Server
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	master, err := envelope.GenerateMasterKey()
	if err != nil {
		t.Fatalf("master key: %v", err)
	}
	sealer, err := envelope.New(master)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	logs := &syncBuffer{}
	st := store.New()
	au := audit.New(logs)
	m := metrics.New()

	cfg := api.Config{
		CreateRate:  100000,
		CreateBurst: 100000,
		ReadRate:    100000,
		ReadBurst:   100000,
	}
	s := api.New(cfg, sealer, st, au, m)
	srv := httptest.NewServer(s.Handler())

	t.Cleanup(srv.Close)
	return &harness{t: t, srv: srv, client: srv.Client(), logs: logs, api: s}
}

type createResp struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	DeletionToken string `json:"deletion_token"`
	MaxViews      int    `json:"max_views"`
	ExpiresAt     string `json:"expires_at"`
	Error         string `json:"error"`
}

func (h *harness) create(content string, maxViews int, ttl int, passphrase string) createResp {
	h.t.Helper()
	body := map[string]any{"content": content}
	if maxViews > 0 {
		body["max_views"] = maxViews
	}
	if ttl > 0 {
		body["ttl_seconds"] = ttl
	}
	if passphrase != "" {
		body["passphrase"] = passphrase
	}
	raw, _ := json.Marshal(body)
	res, err := h.client.Post(h.srv.URL+"/secrets", "application/json", bytes.NewReader(raw))
	if err != nil {
		h.t.Fatalf("create: %v", err)
	}
	defer res.Body.Close()
	var out createResp
	data, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(data, &out); err != nil {
		h.t.Fatalf("create decode: %v (body %q)", err, data)
	}
	return out
}

// getNoRedirect issues a GET that does not follow redirects and identifies as a
// non-browser (so it gets JSON rather than HTML).
func (h *harness) get(id, passphrase string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/s/"+id, nil)
	req.Header.Set("Accept", "application/json")
	if passphrase != "" {
		req.Header.Set("X-Passphrase", passphrase)
	}
	res, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	var payload struct {
		Content string `json:"content"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(data, &payload)
	if payload.Content != "" {
		return res.StatusCode, payload.Content
	}
	return res.StatusCode, payload.Error
}

func (h *harness) del(id, token string) int {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, h.srv.URL+"/s/"+id, nil)
	if token != "" {
		req.Header.Set("X-Deletion-Token", token)
	}
	res, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("delete: %v", err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

// --- correctness ---

func TestCreateAndViewOnce(t *testing.T) {
	h := newHarness(t)
	c := h.create("hello world", 1, 60, "")
	if c.ID == "" || c.URL == "" || c.DeletionToken == "" {
		t.Fatalf("incomplete create response: %+v", c)
	}

	code, body := h.get(c.ID, "")
	if code != http.StatusOK || body != "hello world" {
		t.Fatalf("first view: code=%d body=%q", code, body)
	}
	code, _ = h.get(c.ID, "")
	if code != http.StatusNotFound {
		t.Fatalf("second view should be 404, got %d", code)
	}
}

func TestMaxViewsCount(t *testing.T) {
	h := newHarness(t)
	c := h.create("three times", 3, 60, "")
	for i := 1; i <= 3; i++ {
		code, body := h.get(c.ID, "")
		if code != http.StatusOK || body != "three times" {
			t.Fatalf("view %d: code=%d body=%q", i, code, body)
		}
	}
	if code, _ := h.get(c.ID, ""); code != http.StatusNotFound {
		t.Fatalf("view after max should be 404, got %d", code)
	}
}

func TestPassphraseRequired(t *testing.T) {
	h := newHarness(t)
	c := h.create("classified", 1, 60, "hunter2")

	// Wrong passphrase must not consume the view.
	if code, _ := h.get(c.ID, "wrong"); code != http.StatusNotFound {
		t.Fatalf("wrong passphrase should be 404, got %d", code)
	}
	if code, _ := h.get(c.ID, "alsowrong"); code != http.StatusNotFound {
		t.Fatalf("second wrong passphrase should be 404, got %d", code)
	}

	// The real view must still be available.
	code, body := h.get(c.ID, "hunter2")
	if code != http.StatusOK || body != "classified" {
		t.Fatalf("right passphrase: code=%d body=%q", code, body)
	}
}

func TestRevokeWithToken(t *testing.T) {
	h := newHarness(t)
	c := h.create("revoke me", 1, 60, "")

	if code := h.del(c.ID, "not-the-token"); code != http.StatusNotFound {
		t.Fatalf("wrong token should be 404, got %d", code)
	}
	// Wrong token must not have destroyed the secret.
	if code, _ := h.get(c.ID, ""); code != http.StatusOK {
		t.Fatalf("secret should survive a failed revoke, got %d", code)
	}

	c2 := h.create("revoke me too", 1, 60, "")
	if code := h.del(c2.ID, c2.DeletionToken); code != http.StatusNoContent {
		t.Fatalf("valid revoke should be 204, got %d", code)
	}
	if code, _ := h.get(c2.ID, ""); code != http.StatusNotFound {
		t.Fatalf("revoked secret should be gone, got %d", code)
	}
}

func TestTTLExpiry(t *testing.T) {
	h := newHarness(t)
	c := h.create("expires fast", 1, 1, "")

	time.Sleep(1300 * time.Millisecond)

	if code, _ := h.get(c.ID, ""); code != http.StatusNotFound {
		t.Fatalf("expired secret should be 404, got %d", code)
	}
}

// TestViewOnceRace is the headline requirement: 50 simultaneous GETs on one id
// must yield exactly one successful read.
func TestViewOnceRace(t *testing.T) {
	const readers = 50
	for attempt := 0; attempt < 5; attempt++ {
		h := newHarness(t)
		c := h.create("the one and only", 1, 120, "")

		var wins atomic.Int32
		var failures atomic.Int32
		var start sync.WaitGroup
		start.Add(1)

		var wg sync.WaitGroup
		wg.Add(readers)
		for i := 0; i < readers; i++ {
			go func() {
				defer wg.Done()
				start.Wait()
				req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/s/"+c.ID, nil)
				req.Header.Set("Accept", "application/json")
				res, err := h.client.Do(req)
				if err != nil {
					failures.Add(1)
					return
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				switch {
				case res.StatusCode == http.StatusOK:
					var p struct {
						Content string `json:"content"`
					}
					if json.Unmarshal(body, &p) == nil && p.Content == "the one and only" {
						wins.Add(1)
					} else {
						// A 200 with the wrong body is a critical failure.
						failures.Add(1)
					}
				case res.StatusCode == http.StatusNotFound:
					// expected for the losers
				default:
					// 429 or 5xx would mean the race was not actually exercised
					failures.Add(1)
				}
			}()
		}
		start.Done()
		wg.Wait()

		if got := wins.Load(); got != 1 {
			t.Fatalf("attempt %d: expected exactly 1 winner, got %d (failures=%d)", attempt, got, failures.Load())
		}
		if f := failures.Load(); f != 0 {
			t.Fatalf("attempt %d: %d unexpected outcomes", attempt, f)
		}
	}
}

// TestViewOnceRaceWithMultipleViews checks the boundary: with max_views=10 and
// 50 concurrent readers, exactly 10 must win.
func TestViewOnceRaceWithMultipleViews(t *testing.T) {
	const readers = 50
	const views = 10

	h := newHarness(t)
	c := h.create("multi", views, 120, "")

	var wins atomic.Int32
	var start sync.WaitGroup
	start.Add(1)
	var wg sync.WaitGroup
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			start.Wait()
			req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/s/"+c.ID, nil)
			req.Header.Set("Accept", "application/json")
			res, err := h.client.Do(req)
			if err != nil {
				return
			}
			defer res.Body.Close()
			if res.StatusCode == http.StatusOK {
				wins.Add(1)
			}
		}()
	}
	start.Done()
	wg.Wait()

	if got := wins.Load(); got != views {
		t.Fatalf("expected exactly %d winners, got %d", views, got)
	}
}

// --- ids & uniformity ---

func TestIDsAreUnguessable(t *testing.T) {
	h := newHarness(t)
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		c := h.create(fmt.Sprintf("s%d", i), 1, 60, "")
		if len(c.ID) < 32 {
			t.Fatalf("id too short: %q (%d chars)", c.ID, len(c.ID))
		}
		if seen[c.ID] {
			t.Fatalf("duplicate id: %q", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestNotFoundAndWrongPassphraseAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	real := h.create("x", 1, 60, "correct-horse")

	missing := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	mean := func(ds []time.Duration) time.Duration {
		var total time.Duration
		for _, d := range ds {
			total += d
		}
		return total / time.Duration(len(ds))
	}

	// Same passphrase on a real vs missing id must look alike (status, body,
	// and wall time within tolerance). Checked for empty and non-empty
	// passphrases because each selects a different
	// code path in the KDF.
	for _, passphrase := range []string{"", "wrong-passphrase"} {
		t.Run("passphrase="+passphrase, func(t *testing.T) {
			var dm, dw []time.Duration
			samples := 25

			for i := 0; i < samples; i++ {
				st := time.Now()
				codeMissing, bodyMissing := h.get(missing, passphrase)
				dm = append(dm, time.Since(st))

				st = time.Now()
				codeWrong, bodyWrong := h.get(real.ID, passphrase)
				dw = append(dw, time.Since(st))

				if codeMissing != codeWrong {
					t.Fatalf("status differs: missing=%d wrong-pass=%d", codeMissing, codeWrong)
				}
				if bodyMissing != bodyWrong {
					t.Fatalf("body differs: missing=%q wrong-pass=%q", bodyMissing, bodyWrong)
				}
			}

			m1, m2 := mean(dm), mean(dw)
			ratio := float64(m1) / float64(m2)
			if ratio < 0.25 || ratio > 4 {
				t.Fatalf("timing gap too large: missing=%v wrong=%v ratio=%.2f", m1, m2, ratio)
			}
		})
	}
}

// --- rate limiting ---

func TestRateLimitCreate(t *testing.T) {
	master, _ := envelope.GenerateMasterKey()
	sealer, _ := envelope.New(master)
	st := store.New()
	m := metrics.New()
	cfg := api.Config{CreateRate: 1, CreateBurst: 3, ReadRate: 100, ReadBurst: 100}
	s := api.New(cfg, sealer, st, audit.New(io.Discard), m)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"content":"x","max_views":1,"ttl_seconds":60}`
	var got429 bool
	for i := 0; i < 20; i++ {
		res, err := srv.Client().Post(srv.URL+"/secrets", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			got429 = true
			if res.Header.Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
			break
		}
	}
	if !got429 {
		t.Fatal("expected a 429 within 20 creates at rate=1 burst=3")
	}
}

// TestSpoofedXFFDoesNotBypass is the important one: without trusted proxies,
// every request is one bucket regardless of X-Forwarded-For.
func TestSpoofedXFFDoesNotBypass(t *testing.T) {
	master, _ := envelope.GenerateMasterKey()
	sealer, _ := envelope.New(master)
	st := store.New()
	cfg := api.Config{CreateRate: 1, CreateBurst: 2, ReadRate: 100, ReadBurst: 100, TrustedProxy: ""}
	s := api.New(cfg, sealer, st, audit.New(io.Discard), metrics.New())
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body := `{"content":"x","max_views":1,"ttl_seconds":60}`
	var codes []int
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/secrets", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}

	saw429 := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			saw429 = true
		}
	}
	if !saw429 {
		t.Fatalf("spoofed X-Forwarded-For bypassed the limiter: codes=%v", codes)
	}
}

// --- no plaintext / log hygiene ---

func TestSecretNeverAppearsInAuditLog(t *testing.T) {
	h := newHarness(t)
	const canary = "CANARY-8f4a1b2c-very-secret-value"
	const pass = "PASSPHRASE-9z8y7x"

	c := h.create(canary, 1, 60, pass)
	if code, _ := h.get(c.ID, pass); code != http.StatusOK {
		t.Fatalf("view failed: %d", code)
	}
	h.del(c.ID, c.DeletionToken)

	logs := h.logs.String()
	if strings.Contains(logs, canary) {
		t.Fatal("canary leaked into the audit log")
	}
	if strings.Contains(logs, pass) {
		t.Fatal("passphrase leaked into the audit log")
	}
	if strings.Contains(logs, c.ID) {
		t.Fatal("raw secret id leaked into the audit log")
	}
	if strings.Contains(logs, c.DeletionToken) {
		t.Fatal("deletion token leaked into the audit log")
	}
	// Sanity: the log is not simply empty.
	if !strings.Contains(logs, "secret.create") {
		t.Fatal("audit log did not record the create event")
	}
}

// --- headers ---

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	c := h.create("x", 1, 60, "")

	res, err := h.client.Get(h.srv.URL + "/s/" + c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()

	want := map[string]string{
		"Cache-Control":          "no-store, no-cache, must-revalidate, private, max-age=0",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s: got %q want %q", k, got, v)
		}
	}
	if csp := res.Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("missing Content-Security-Policy on the HTML UI")
	}
}

// TestBrowserCannotProbeExistence checks the HTML path specifically: a real
// passphrase-protected secret, a completely made-up id, and a wrong-passphrase
// attempt must all render the same status and the same page.
func TestBrowserCannotProbeExistence(t *testing.T) {
	h := newHarness(t)
	real := h.create("guarded", 5, 300, "a-passphrase")

	get := func(id, passphrase string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/s/"+id, nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		if passphrase != "" {
			req.Header.Set("X-Passphrase", passphrase)
		}
		res, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body)
	}

	codeReal, bodyReal := get(real.ID, "")
	codeFake, bodyFake := get("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "")
	codeWrong, bodyWrong := get(real.ID, "not-the-passphrase")

	if codeReal != codeFake || codeReal != codeWrong {
		t.Fatalf("status differs: real=%d fake=%d wrong-pass=%d", codeReal, codeFake, codeWrong)
	}
	if bodyReal != bodyFake {
		t.Fatalf("unlock page differs between a real and a fake id (lengths %d vs %d)",
			len(bodyReal), len(bodyFake))
	}
	if bodyReal != bodyWrong {
		t.Fatalf("wrong-passphrase page differs from unlock page (lengths %d vs %d)",
			len(bodyWrong), len(bodyReal))
	}

	// And after all of that probing, the secret must still be readable.
	code, body := h.get(real.ID, "a-passphrase")
	if code != http.StatusOK || body != "guarded" {
		t.Fatalf("probing burned or broke the secret: code=%d body=%q", code, body)
	}
}

// HEAD must never consume a one-time secret. Link unfurlers, antivirus
// scanners and `curl -I` all issue HEAD against URLs they merely saw; if that
// burned the view, the recipient would find the secret already gone.
func TestHeadDoesNotBurnSecret(t *testing.T) {
	h := newHarness(t)
	c := h.create("head-must-not-burn", 1, 120, "")

	req, _ := http.NewRequest(http.MethodHead, h.srv.URL+"/s/"+c.ID, nil)
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	res.Body.Close()

	if res.StatusCode == http.StatusOK {
		t.Fatal("HEAD returned 200; want non-OK (must not consume a view)")
	}

	// The secret must still be readable.
	code, body := h.get(c.ID, "")
	if code != http.StatusOK || body != "head-must-not-burn" {
		t.Fatalf("HEAD destroyed the secret: code=%d body=%q", code, body)
	}
}

// A passphrase must not be accepted from the query string: it would land in
// proxy access logs, browser history and Referer headers.
func TestPassphraseInQueryStringRejected(t *testing.T) {
	h := newHarness(t)
	c := h.create("query-secret", 5, 120, "sesame")

	// Sending it the old way must not work.
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/s/"+c.ID+"?p=c2VzYW1l", nil)
	req.Header.Set("Accept", "application/json")
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("passphrase from the query string was accepted")
	}

	// The header form must still work, and must not have been burned.
	code, body := h.get(c.ID, "sesame")
	if code != http.StatusOK || body != "query-secret" {
		t.Fatalf("header passphrase failed: code=%d body=%q", code, body)
	}
}

func TestAPIClientCannotProbeExistence(t *testing.T) {
	h := newHarness(t)
	real := h.create("guarded", 5, 120, "a-passphrase")

	get := func(id string) (int, string, string) {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/s/"+id, nil)
		req.Header.Set("Accept", "application/json")
		res, err := h.client.Do(req)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header.Get("Content-Type"), string(body)
	}

	c1, ct1, b1 := get(real.ID)
	c2, ct2, b2 := get("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")

	if c1 != c2 {
		t.Fatalf("status mismatch: real=%d fake=%d", c1, c2)
	}
	if ct1 != ct2 {
		t.Fatalf("content-type mismatch: real=%q fake=%q", ct1, ct2)
	}
	if b1 != b2 {
		t.Fatalf("body mismatch: real=%q fake=%q", b1, b2)
	}
}

func TestDeleteIsRateLimited(t *testing.T) {
	master, _ := envelope.GenerateMasterKey()
	sealer, _ := envelope.New(master)
	cfg := api.Config{CreateRate: 100, CreateBurst: 100, ReadRate: 1, ReadBurst: 3}
	s := api.New(cfg, sealer, store.New(), audit.New(io.Discard), metrics.New())
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	saw429 := false
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/s/nonexistent", nil)
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("DELETE was never rate limited")
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t)
	res, err := h.client.Get(h.srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", res.StatusCode)
	}
}

// POST /secrets must refuse non-JSON content types so a cross-origin
// text/plain POST cannot skip CORS preflight and burn create quota.
func TestCreateRequiresJSONContentType(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/secrets", strings.NewReader(`{"content":"x","max_views":1,"ttl_seconds":60}`))
	req.Header.Set("Content-Type", "text/plain")
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d, want 415", res.StatusCode)
	}
}

// Without PUBLIC_BASE_URL, a hostile Host header must not appear in share URLs.
func TestShareURLIgnoresHostileHost(t *testing.T) {
	master, _ := envelope.GenerateMasterKey()
	sealer, _ := envelope.New(master)
	cfg := api.Config{
		PublicBaseURL: "", // force the fallback path
		CreateRate:    1000, CreateBurst: 1000,
		ReadRate: 1000, ReadBurst: 1000,
	}
	s := api.New(cfg, sealer, store.New(), audit.New(io.Discard), metrics.New())
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/secrets", strings.NewReader(`{"content":"x","max_views":1,"ttl_seconds":60}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "attacker.example"
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	var out createResp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(out.URL, "attacker.example") {
		t.Fatalf("hostile Host leaked into share URL: %s", out.URL)
	}
	if !strings.Contains(out.URL, "localhost") && !strings.Contains(out.URL, "127.0.0.1") {
		t.Fatalf("expected a loopback share URL, got %s", out.URL)
	}
}

func TestMetricsTokenGate(t *testing.T) {
	master, _ := envelope.GenerateMasterKey()
	sealer, _ := envelope.New(master)
	cfg := api.Config{
		MetricsToken: "s3cret-metrics",
		CreateRate:   1000, CreateBurst: 1000,
		ReadRate: 1000, ReadBurst: 1000,
	}
	s := api.New(cfg, sealer, store.New(), audit.New(io.Discard), metrics.New())
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("open metrics returned %d, want 401", res.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret-metrics")
	res, err = srv.Client().Do(req)
	if err != nil {
		t.Fatalf("metrics auth: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorized metrics returned %d", res.StatusCode)
	}
}

func TestMultipartOpenRejected(t *testing.T) {
	h := newHarness(t)
	c := h.create("mp", 1, 60, "pass")
	body := strings.NewReader("--bound\r\nContent-Disposition: form-data; name=\"passphrase\"\r\n\r\npass\r\n--bound--\r\n")
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/s/"+c.ID, body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=bound")
	req.Header.Set("Accept", "application/json")
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("multipart open returned %d, want 415", res.StatusCode)
	}
	// Secret must still be intact.
	code, content := h.get(c.ID, "pass")
	if code != http.StatusOK || content != "mp" {
		t.Fatalf("multipart attempt damaged the secret: %d %q", code, content)
	}
}

func TestMetricsHasNoSecretData(t *testing.T) {
	h := newHarness(t)
	const canary = "METRICS-CANARY-1234"
	c := h.create(canary, 1, 60, "")
	h.get(c.ID, "")

	res, err := h.client.Get(h.srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if bytes.Contains(data, []byte(canary)) {
		t.Fatal("canary leaked into /metrics")
	}
	if bytes.Contains(data, []byte(c.ID)) {
		t.Fatal("secret id leaked into /metrics")
	}
	if !bytes.Contains(data, []byte("otss_secrets_created_total")) {
		t.Fatal("metrics missing expected counters")
	}
}
