package api

import (
	"encoding/json"
	"html"
	"net/http"
	"strconv"
	"strings"

	"github.com/Ale0011/otss/internal/audit"
	"github.com/Ale0011/otss/internal/envelope"
	"github.com/Ale0011/otss/internal/store"
)

// handleCreateForm is the browser-facing twin of POST /secrets.
//
// It exists so the human UI needs no JavaScript at all, which lets the CSP ship
// script-src 'none'. It shares every validation and crypto path with the JSON
// endpoint; the only difference is the response format.
func (s *Server) handleCreateForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	ip := s.ips.ClientIP(r)
	if !s.limit(s.createRL, "c:"+ip, ip, "create", w) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		s.cBadRequest.Inc("")
		s.renderGenericPage(w, http.StatusBadRequest, "Bad request", "The form could not be read.")
		return
	}

	content := r.PostForm.Get("content")
	if len(content) == 0 {
		s.cBadRequest.Inc("")
		s.renderGenericPage(w, http.StatusBadRequest, "Missing content", "Paste something to share first.")
		return
	}
	if len(content) > maxContentBytes {
		s.cBadRequest.Inc("")
		s.renderGenericPage(w, http.StatusBadRequest, "Too large",
			"Secrets are capped at 64 KiB.")
		return
	}

	ttl := 86400
	if v := strings.TrimSpace(r.PostForm.Get("ttl_seconds")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < minTTL || n > maxTTL {
			s.cBadRequest.Inc("")
			s.renderGenericPage(w, http.StatusBadRequest, "Invalid TTL",
				"TTL must be between 1 and 604800 seconds.")
			return
		}
		ttl = n
	}

	views := 1
	if v := strings.TrimSpace(r.PostForm.Get("max_views")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < minViews || n > maxViews {
			s.cBadRequest.Inc("")
			s.renderGenericPage(w, http.StatusBadRequest, "Invalid view count",
				"Views must be between 1 and 100.")
			return
		}
		views = n
	}

	passphrase := r.PostForm.Get("passphrase")
	if len(passphrase) > maxPassphrase {
		s.cBadRequest.Inc("")
		s.renderGenericPage(w, http.StatusBadRequest, "Passphrase too long",
			"Passphrases are capped at 1024 bytes.")
		return
	}

	id, err := store.NewID()
	if err != nil {
		s.renderGenericPage(w, http.StatusInternalServerError, "Error", "Could not create the secret.")
		return
	}
	deletionToken, err := store.NewDeletionToken()
	if err != nil {
		s.renderGenericPage(w, http.StatusInternalServerError, "Error", "Could not create the secret.")
		return
	}

	plaintext := []byte(content)
	wrapped, nonce, ct, err := s.sealer.Seal(id, passphrase, plaintext)
	envelope.Zero(plaintext)
	if err != nil {
		s.renderGenericPage(w, http.StatusInternalServerError, "Error", "Could not create the secret.")
		return
	}

	rec := store.NewRecord(
		id, passphrase != "",
		wrapped, nonce, ct,
		envelope.DeletionHash(deletionToken),
		uint32(views), timeSeconds(ttl),
	)
	if err := s.store.Insert(rec); err != nil {
		s.renderGenericPage(w, http.StatusInternalServerError, "Error", "Could not create the secret.")
		return
	}

	s.cCreate.Inc("")
	s.audit.Log(audit.Entry{
		Event: audit.EvCreate,
		IDTag: s.sealer.IDTag(id),
		IP:    ip,
		Note:  "max_views=" + strconv.Itoa(views) + " ttl=" + strconv.Itoa(ttl) + " via=form",
	})

	base := s.shareBase(r)
	shareURL := base + "/s/" + id

	setHTMLHeaders(w)
	w.WriteHeader(http.StatusCreated)
	var b []byte
	b = append(b, pageShellTop...)
	b = append(b, html.EscapeString("Link created")...)
	b = append(b, pageShellMid...)
	b = append(b, `<h1>Link created</h1>
<p class="sub">Copy it now. These values are shown exactly once.</p>
<div class="card"><label>Share link</label><pre id="u"></pre>`...)
	b = append(b, `<label style="margin-top:16px">Deletion token (keep it secret)</label><pre id="d"></pre></div>
<div class="warn">Reloading this page will not show the link again. The deletion token is the only way to revoke the secret before it is read.</div>`...)
	b = append(b, pageShellBottom...)

	page := string(b)
	page = strings.Replace(page, `<pre id="u"></pre>`, `<pre id="u">`+html.EscapeString(shareURL)+`</pre>`, 1)
	page = strings.Replace(page, `<pre id="d"></pre>`, `<pre id="d">`+html.EscapeString(deletionToken)+`</pre>`, 1)
	_, _ = w.Write([]byte(page))
}

var _ = json.Marshal
