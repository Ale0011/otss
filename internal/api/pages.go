package api

import (
	"html"
	"net/http"
	"strconv"
)

// The UI is server-rendered with a strict CSP and no inline script. Every page
// that could ever display a secret is marked no-store by the middleware, and the
// secret itself is inserted with html.EscapeString so it cannot break out.
const cspValue = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'; script-src 'none'"

func setHTMLHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", cspValue)
}

const pageShellTop = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>`

const pageShellMid = `</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #0b0d10; color: #e6e8eb; padding: 24px;
  }
  main { width: 100%; max-width: 640px; }
  h1 { font-size: 20px; margin: 0 0 6px; letter-spacing: -0.01em; }
  p.sub { margin: 0 0 24px; color: #9aa4b2; }
  .card {
    background: #14181d; border: 1px solid #232a33; border-radius: 12px;
    padding: 20px;
  }
  pre {
    margin: 0; padding: 16px; border-radius: 8px; background: #0a0c0f;
    border: 1px solid #232a33; overflow-x: auto; white-space: pre-wrap;
    word-break: break-word; font: 13px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  label { display: block; font-size: 13px; color: #9aa4b2; margin-bottom: 6px; }
  input[type=password], input[type=text] {
    width: 100%; padding: 10px 12px; border-radius: 8px; background: #0a0c0f;
    border: 1px solid #2b333d; color: #e6e8eb; font: inherit;
  }
  input:focus { outline: 2px solid #3b82f6; outline-offset: 1px; border-color: #3b82f6; }
  button {
    margin-top: 14px; width: 100%; padding: 10px 14px; border-radius: 8px;
    border: 0; background: #3b82f6; color: white; font: inherit; font-weight: 600;
    cursor: pointer;
  }
  button:hover { background: #2f6fd8; }
  .warn {
    margin-top: 16px; padding: 12px 14px; border-radius: 8px;
    background: #2a1a12; border: 1px solid #5a3220; color: #f0b48a; font-size: 13px;
  }
  .ok {
    margin-top: 16px; padding: 12px 14px; border-radius: 8px;
    background: #12241a; border: 1px solid #235c39; color: #7fd39b; font-size: 13px;
  }
  footer { margin-top: 20px; color: #6b7482; font-size: 12px; text-align: center; }
</style>
</head>
<body>
<main>
`

const pageShellBottom = `</main>
</body>
</html>
`

func (s *Server) renderSecretPage(w http.ResponseWriter, content []byte, remaining uint32) {
	setHTMLHeaders(w)
	w.WriteHeader(http.StatusOK)

	left := "This message has now been destroyed."
	if remaining > 0 {
		left = "Views remaining after this one: " + strconv.FormatUint(uint64(remaining), 10) + "."
	}

	buf := make([]byte, 0, 4096+len(content))
	buf = append(buf, pageShellTop...)
	buf = append(buf, html.EscapeString("Your secret")...)
	buf = append(buf, pageShellMid...)
	buf = append(buf, `<h1>Your secret</h1>
<p class="sub">Read it now. It is gone after this page.</p>
<div class="card"><pre>`...)
	buf = append(buf, html.EscapeString(string(content))...)
	buf = append(buf, `</pre></div>
<div class="warn">`...)
	buf = append(buf, html.EscapeString(left)...)
	buf = append(buf, ` Do not reload — reloading will not bring it back.</div>`...)
	buf = append(buf, `<footer>Not stored, not recoverable.</footer>`...)
	buf = append(buf, pageShellBottom...)
	_, _ = w.Write(buf)
}

// renderUnlockPage is the unlock form for passphrase-gated reads.
func (s *Server) renderUnlockPage(w http.ResponseWriter, r *http.Request, id, errMsg string) {
	setHTMLHeaders(w)
	w.WriteHeader(http.StatusOK)

	var b []byte
	b = append(b, pageShellTop...)
	b = append(b, html.EscapeString("Unlock secret")...)
	b = append(b, pageShellMid...)
	b = append(b, `<h1>Unlock secret</h1>
<p class="sub">This link is protected. Enter the passphrase you were given.</p>
<div class="card">
  <form method="POST" autocomplete="off">
    <label for="p">Passphrase</label>
    <input id="p" name="passphrase" type="password" autocomplete="off" autofocus
           spellcheck="false" autocapitalize="off" required>
    <button type="submit">Reveal secret</button>
  </form>`...)
	if errMsg != "" {
		b = append(b, `<div class="warn">`...)
		b = append(b, html.EscapeString(errMsg)...)
		b = append(b, `</div>`...)
	}
	b = append(b, `</div>
<footer>One wrong passphrase does not destroy the secret.</footer>`...)
	b = append(b, pageShellBottom...)
	_, _ = w.Write(b)
}

func (s *Server) renderGenericPage(w http.ResponseWriter, status int, title, msg string) {
	setHTMLHeaders(w)
	w.WriteHeader(status)
	var b []byte
	b = append(b, pageShellTop...)
	b = append(b, html.EscapeString(title)...)
	b = append(b, pageShellMid...)
	b = append(b, `<h1>`...)
	b = append(b, html.EscapeString(title)...)
	b = append(b, `</h1>
<div class="card"><p style="margin:0;color:#9aa4b2">`...)
	b = append(b, html.EscapeString(msg)...)
	b = append(b, `</p></div>`...)
	b = append(b, pageShellBottom...)
	_, _ = w.Write(b)
}

// handleIndex serves a tiny creation form so the build is usable by a human, and
// nothing else at the root. It deliberately uses no JavaScript: the form posts
// to /secrets/form and the server renders the result. That keeps the CSP at
// script-src 'none' with no nonce bookkeeping.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	setHTMLHeaders(w)
	w.WriteHeader(http.StatusOK)

	var b []byte
	b = append(b, pageShellTop...)
	b = append(b, html.EscapeString("One-time secret")...)
	b = append(b, pageShellMid...)
	b = append(b, `<h1>One-time secret</h1>
<p class="sub">Create a link that self-destructs after it is read.</p>
<div class="card">
  <form method="POST" action="/secrets/form" autocomplete="off">
    <label for="c">Secret</label>
    <textarea id="c" name="content" rows="5" required
      style="width:100%;padding:10px 12px;border-radius:8px;background:#0a0c0f;border:1px solid #2b333d;color:#e6e8eb;font:inherit;resize:vertical"></textarea>
    <div style="display:flex;gap:12px;margin-top:12px">
      <div style="flex:1">
        <label for="v">Views</label>
        <input id="v" name="max_views" type="text" inputmode="numeric" value="1">
      </div>
      <div style="flex:1">
        <label for="t">TTL (seconds)</label>
        <input id="t" name="ttl_seconds" type="text" inputmode="numeric" value="86400">
      </div>
    </div>
    <label for="p2" style="margin-top:12px">Passphrase (optional)</label>
    <input id="p2" name="passphrase" type="password" autocomplete="off">
    <button type="submit">Create link</button>
  </form>
</div>
<footer>Content is encrypted in memory and never logged.</footer>`...)
	b = append(b, pageShellBottom...)
	_, _ = w.Write(b)
}
