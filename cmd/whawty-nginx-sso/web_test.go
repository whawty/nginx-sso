//
// Copyright (c) 2026 whawty contributors (see AUTHORS file)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.nginx-sso nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/whawty/nginx-sso/cookie"
)

type testAuthBackend map[string]string

func (b testAuthBackend) Authenticate(username, password string) error {
	if p, ok := b[username]; ok && p == password {
		return nil
	}
	return errors.New("invalid username or password")
}

func newTestStore(t *testing.T, domain string) *cookie.Store {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPem := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	conf := &cookie.Config{
		Domain:  domain,
		Keys:    []cookie.SignerVerifierConfig{{Name: "test", Ed25519: &cookie.Ed25519Config{PrivKeyData: &keyPem}}},
		Backend: cookie.StoreBackendConfig{InMemory: &cookie.InMemoryBackendConfig{}},
	}
	st, err := cookie.NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// newTestHandler returns the web handler for conf with a fresh in-memory
// session store and the users alice and o'brien&<co>, both with the password
// secret.
func newTestHandler(t *testing.T, conf WebConfig, cookieDomain string) http.Handler {
	t.Helper()
	h, _ := newTestHandlerAndStore(t, conf, cookieDomain)
	return h
}

func newTestHandlerAndStore(t *testing.T, conf WebConfig, cookieDomain string) (http.Handler, *cookie.Store) {
	t.Helper()
	prom, err := newMetricsHandler(nil)
	if err != nil {
		t.Fatal(err)
	}
	store := newTestStore(t, cookieDomain)
	h, err := newWebHandler(&conf, prom, store, testAuthBackend{"alice": "secret", "o'brien&<co>": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	return h, store
}

// request sends a request to h. If form is not nil it is sent as the body
// of a form submission.
func request(h http.Handler, method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// login logs in alice and returns the session cookie.
func login(t *testing.T, h http.Handler, loginURL string) *http.Cookie {
	t.Helper()
	rec := request(h, http.MethodPost, loginURL, url.Values{"username": {"alice"}, "password": {"secret"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: got status %d, want %d: %s", rec.Code, http.StatusSeeOther, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookie.DefaultCookieName && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatal("login: no session cookie set")
	return nil
}

type routeTest struct {
	method   string
	path     string
	status   int
	location string // only checked if not empty
}

func checkRoutes(t *testing.T, h http.Handler, tests []routeTest) {
	t.Helper()
	for _, test := range tests {
		rec := request(h, test.method, test.path, nil)
		if rec.Code != test.status {
			t.Errorf("%s %s: got status %d, want %d", test.method, test.path, rec.Code, test.status)
		}
		if loc := rec.Header().Get("Location"); test.location != "" && loc != test.location {
			t.Errorf("%s %s: got Location %q, want %q", test.method, test.path, loc, test.location)
		}
	}
}

func TestNormalizeBasePath(t *testing.T) {
	tests := map[string]string{
		"":           "",
		"/":          "",
		" / ":        "",
		"sso":        "/sso",
		"/sso":       "/sso",
		"/sso/":      "/sso",
		"//a//b/":    "/a/b",
		"/a/./b/../": "/a",
		"/../sso":    "/sso",
	}
	for in, want := range tests {
		if got := normalizeBasePath(in); got != want {
			t.Errorf("normalizeBasePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWebHandlerInvalidBasePath(t *testing.T) {
	prom, _ := newMetricsHandler(nil)
	for _, basePath := range []string{"/sso/:id", "/sso/*all"} {
		conf := WebConfig{BasePath: basePath}
		if _, err := newWebHandler(&conf, prom, newTestStore(t, ""), testAuthBackend{}); err == nil {
			t.Errorf("base path %q: no error", basePath)
		}
	}
}

func TestWebHandlerRoutes(t *testing.T) {
	h := newTestHandler(t, WebConfig{BasePath: "/sso/"}, "")
	checkRoutes(t, h, []routeTest{
		{http.MethodGet, "/sso", http.StatusSeeOther, "sso/"},
		{http.MethodGet, "/sso/", http.StatusSeeOther, "login"},
		{http.MethodGet, "/sso/login", http.StatusOK, ""},
		{http.MethodGet, "/sso/ui/css/main.css", http.StatusOK, ""},
		{http.MethodGet, "/sso/auth", http.StatusUnauthorized, ""},
		{http.MethodGet, "/sso/logout", http.StatusSeeOther, "login"},
		{http.MethodGet, "/sso/sessions", http.StatusUnauthorized, ""},
		{http.MethodGet, "/sso/revocations", http.StatusUnauthorized, ""},
		// nothing outside the base path
		{http.MethodGet, "/", http.StatusNotFound, ""},
		{http.MethodGet, "/login", http.StatusNotFound, ""},
		{http.MethodGet, "/auth", http.StatusNotFound, ""},
		{http.MethodGet, "/ui/css/main.css", http.StatusNotFound, ""},
		{http.MethodGet, "/ssox/login", http.StatusNotFound, ""},
		// no absolute redirects to fix up trailing slashes
		{http.MethodGet, "/sso/login/", http.StatusNotFound, ""},
	})

	h = newTestHandler(t, WebConfig{BasePath: "/apps/single sign-on"}, "")
	checkRoutes(t, h, []routeTest{
		{http.MethodGet, "/apps/single%20sign-on", http.StatusSeeOther, "single%20sign-on/"},
		{http.MethodGet, "/apps/single%20sign-on/login", http.StatusOK, ""},
	})
}

// Without a base path the web interface also works behind a proxy which
// strips a path prefix, as long as all redirects are relative.
func TestWebHandlerBehindStrippingProxy(t *testing.T) {
	h := newTestHandler(t, WebConfig{}, "")
	checkRoutes(t, h, []routeTest{
		{http.MethodGet, "/", http.StatusSeeOther, "login"},
		{http.MethodGet, "/login", http.StatusOK, ""},
		{http.MethodGet, "/ui/css/main.css", http.StatusOK, ""},
		{http.MethodGet, "/auth", http.StatusUnauthorized, ""},
		{http.MethodGet, "/logout", http.StatusSeeOther, "login"},
	})

	rec := request(h, http.MethodPost, "/login", url.Values{"username": {"alice"}, "password": {"secret"}})
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "login" {
		t.Errorf("login: got status %d and Location %q, want %d and %q", rec.Code, loc, http.StatusSeeOther, "login")
	}
}

func TestLoginAndAuth(t *testing.T) {
	h := newTestHandler(t, WebConfig{BasePath: "/sso"}, "")

	rec := request(h, http.MethodPost, "/sso/login", url.Values{"username": {"alice"}, "password": {"wrong"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("login with wrong password: got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	session := login(t, h, "/sso/login")
	if session.Path != "/" || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie: got path %q, HttpOnly %t and SameSite %v, want /, true and Lax", session.Path, session.HttpOnly, session.SameSite)
	}

	rec = request(h, http.MethodGet, "/sso/auth", nil, session)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Username") != "alice" {
		t.Errorf("auth: got status %d and X-Username %q, want %d and alice", rec.Code, rec.Header().Get("X-Username"), http.StatusOK)
	}

	rec = request(h, http.MethodGet, "/sso/login", nil, session)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "alice") {
		t.Errorf("logged-in page: got status %d, want %d and a page mentioning alice", rec.Code, http.StatusOK)
	}

	rec = request(h, http.MethodGet, "/sso/logout", nil, session)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("logout: got status %d, want %d", rec.Code, http.StatusSeeOther)
	}
	rec = request(h, http.MethodGet, "/sso/auth", nil, session)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("auth after logout: got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// Links in the pages must be relative, otherwise they break behind proxies
// which strip a path prefix.
func TestTemplatesUseRelativeURLs(t *testing.T) {
	absolute := regexp.MustCompile(`(?i)\b(?:href|src|action)\s*=\s*["']?/`)
	h := newTestHandler(t, WebConfig{}, "")

	rec := request(h, http.MethodGet, "/login", nil)
	if m := absolute.FindString(rec.Body.String()); m != "" {
		t.Errorf("login page contains absolute URL: %s", m)
	}

	session := login(t, h, "/login")
	login(t, h, "/login") // so there is another session in the list
	rec = request(h, http.MethodGet, "/login", nil, session)
	if m := absolute.FindString(rec.Body.String()); m != "" {
		t.Errorf("logged-in page contains absolute URL: %s", m)
	}
}

func TestIsSafeRedirect(t *testing.T) {
	safe := []string{
		"/",
		"/wiki/Main_Page?action=edit#top",
		"login",
		"../other/",
		"https://example.com/",
		"https://wiki.example.com/x?y=z",
		"http://WIKI.Example.COM:8080/x",
		"HTTPS://a.b.example.com",
	}
	unsafe := []string{
		"",
		"//evil.com/",
		"///evil.com/",
		"/\\evil.com/",
		"\\\\evil.com/",
		"/\t/evil.com/",
		"/\n/evil.com/",
		" https://wiki.example.com/",
		"https://evil.com/",
		"https://example.com.evil.net/",
		"https://evilexample.com/",
		"https://wiki.example.com@evil.com/",
		"https://user:pass@wiki.example.com/",
		"https:wiki.example.com",
		"https:///evil.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"ftp://wiki.example.com/",
	}
	for _, domain := range []string{"example.com", ".example.com", "Example.COM"} {
		for _, target := range safe {
			if !isSafeRedirect(target, domain, "login.example.com") {
				t.Errorf("cookie domain %q: %q is safe but was rejected", domain, target)
			}
		}
		for _, target := range unsafe {
			if isSafeRedirect(target, domain, "login.example.com") {
				t.Errorf("cookie domain %q: %q is unsafe but was accepted", domain, target)
			}
		}
	}

	// without a cookie domain only the host of the request gets the cookie
	for target, want := range map[string]bool{
		"/wiki/":                           true,
		"https://login.example.com/x":      true,
		"https://LOGIN.example.com:8443/x": true,
		"https://wiki.example.com/x":       false,
		"https://example.com/x":            false,
	} {
		if got := isSafeRedirect(target, "", "login.example.com:443"); got != want {
			t.Errorf("no cookie domain: isSafeRedirect(%q) = %t, want %t", target, got, want)
		}
	}
}

func TestRedirectTargets(t *testing.T) {
	h := newTestHandler(t, WebConfig{}, "example.com")
	creds := func(redirect string) url.Values {
		return url.Values{"username": {"alice"}, "password": {"secret"}, "redirect": {redirect}}
	}

	for redirect, want := range map[string]string{
		"https://wiki.example.com/x": "https://wiki.example.com/x",
		"/x":                         "/x",
		"https://evil.com/x":         "login",
		"//evil.com/x":               "login",
	} {
		rec := request(h, http.MethodPost, "/login", creds(redirect))
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != want {
			t.Errorf("login with redirect %q: got status %d and Location %q, want %d and %q", redirect, rec.Code, loc, http.StatusSeeOther, want)
		}

		rec = request(h, http.MethodGet, "/logout?redir="+url.QueryEscape(redirect), nil)
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != want {
			t.Errorf("logout with redir %q: got status %d and Location %q, want %d and %q", redirect, rec.Code, loc, http.StatusSeeOther, want)
		}
	}

	// the login form must not carry on unsafe targets
	rec := request(h, http.MethodGet, "/login?redir="+url.QueryEscape("https://evil.com/x"), nil)
	if strings.Contains(rec.Body.String(), "evil.com") {
		t.Error("login form contains unsafe redirect target")
	}
	rec = request(h, http.MethodPost, "/login", url.Values{"username": {"alice"}, "password": {"wrong"}, "redirect": {"https://evil.com/x"}})
	if strings.Contains(rec.Body.String(), "evil.com") {
		t.Error("login form shown after failed login contains unsafe redirect target")
	}
	rec = request(h, http.MethodGet, "/login?redir="+url.QueryEscape("https://wiki.example.com/x"), nil)
	if !strings.Contains(rec.Body.String(), "https://wiki.example.com/x") {
		t.Error("login form lacks safe redirect target")
	}
}

// sessionID returns the ID of the session in the cookie c.
func sessionID(t *testing.T, store *cookie.Store, c *http.Cookie) string {
	t.Helper()
	value, err := url.QueryUnescape(c.Value) // gin escapes cookie values
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Verify(value)
	if err != nil {
		t.Fatal(err)
	}
	return session.ID.String()
}

func checkAuth(t *testing.T, h http.Handler, session *http.Cookie, want int, what string) {
	t.Helper()
	if rec := request(h, http.MethodGet, "/auth", nil, session); rec.Code != want {
		t.Errorf("%s: auth returned status %d, want %d", what, rec.Code, want)
	}
}

func TestRevokeOtherSession(t *testing.T) {
	h, store := newTestHandlerAndStore(t, WebConfig{}, "")
	own := login(t, h, "/login")
	other := login(t, h, "/login")
	otherID := sessionID(t, store, other)

	rec := request(h, http.MethodGet, "/logout?id="+otherID, nil, own)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("revoke using GET: got status %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	checkAuth(t, h, other, http.StatusOK, "other session after revoke using GET")
	checkAuth(t, h, own, http.StatusOK, "own session after revoke using GET")

	rec = request(h, http.MethodPost, "/logout", url.Values{"id": {"bogus"}}, own)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("revoke with invalid ID: got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	rec = request(h, http.MethodPost, "/logout", url.Values{"id": {otherID}}, own)
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "login" {
		t.Errorf("revoke: got status %d and Location %q, want %d and login", rec.Code, loc, http.StatusSeeOther)
	}
	checkAuth(t, h, other, http.StatusUnauthorized, "other session after revoke")
	checkAuth(t, h, own, http.StatusOK, "own session after revoke")

	// without an ID the session of the request is revoked
	rec = request(h, http.MethodPost, "/logout", url.Values{"redir": {"/somewhere"}}, own)
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "/somewhere" {
		t.Errorf("logout using POST: got status %d and Location %q, want %d and /somewhere", rec.Code, loc, http.StatusSeeOther)
	}
	checkAuth(t, h, own, http.StatusUnauthorized, "own session after logout using POST")
}

func TestCrossOriginRequests(t *testing.T) {
	h, store := newTestHandlerAndStore(t, WebConfig{}, "")
	own := login(t, h, "/login")
	other := login(t, h, "/login")
	otherID := sessionID(t, store, other)

	post := func(target string, form url.Values, header, value string) int {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(header, value)
		req.AddCookie(own)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	creds := url.Values{"username": {"alice"}, "password": {"secret"}}
	revoke := url.Values{"id": {otherID}}

	for _, hdr := range [][2]string{
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "same-site"},
		{"Origin", "https://evil.com"}, // browsers without Sec-Fetch-Site
	} {
		if code := post("/login", creds, hdr[0], hdr[1]); code != http.StatusForbidden {
			t.Errorf("login with %s: %s: got status %d, want %d", hdr[0], hdr[1], code, http.StatusForbidden)
		}
		if code := post("/logout", revoke, hdr[0], hdr[1]); code != http.StatusForbidden {
			t.Errorf("revoke with %s: %s: got status %d, want %d", hdr[0], hdr[1], code, http.StatusForbidden)
		}
		checkAuth(t, h, other, http.StatusOK, "other session after cross-origin revoke")
	}

	if code := post("/login", creds, "Sec-Fetch-Site", "same-origin"); code != http.StatusSeeOther {
		t.Errorf("login with Sec-Fetch-Site: same-origin: got status %d, want %d", code, http.StatusSeeOther)
	}
	if code := post("/logout", revoke, "Origin", "http://example.com"); code != http.StatusSeeOther {
		t.Errorf("revoke with matching Origin: got status %d, want %d", code, http.StatusSeeOther)
	}
	checkAuth(t, h, other, http.StatusUnauthorized, "other session after same-origin revoke")
}

func TestRevocationsAuthorization(t *testing.T) {
	conf := WebConfig{}
	conf.Revocations.Tokens = []string{"", "secret-token"}
	h := newTestHandler(t, conf, "")

	for header, want := range map[string]int{
		"":                    http.StatusUnauthorized,
		"Bearer":              http.StatusUnauthorized,
		"Bearer ":             http.StatusUnauthorized, // must not match the empty token
		"Bearer secret":       http.StatusUnauthorized,
		"Bearer secret-token": http.StatusOK,
		"Basic secret-token":  http.StatusUnauthorized,
	} {
		req := httptest.NewRequest(http.MethodGet, "/revocations", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Authorization: %q: got status %d, want %d", header, rec.Code, want)
		}
	}
}

func TestAuthLoginRedir(t *testing.T) {
	h := newTestHandler(t, WebConfig{}, "")
	uri := "/wiki/page?a=1&b=x%26y"
	tests := []struct {
		headers map[string]string
		want    string
	}{
		{map[string]string{"X-Origin-URI": uri, "X-Host": "wiki.example.com", "X-Forwarded-Proto": "https"}, "https://wiki.example.com" + uri},
		{map[string]string{"X-Origin-URI": uri, "X-Host": "wiki.example.com", "X-Forwarded-Proto": "http"}, "http://wiki.example.com" + uri},
		{map[string]string{"X-Origin-URI": uri}, uri},
		{map[string]string{"X-Origin-URI": uri, "X-Host": "wiki.example.com"}, uri},
		{map[string]string{"X-Origin-URI": uri, "X-Host": "wiki.example.com", "X-Forwarded-Proto": "javascript"}, uri},
		{map[string]string{"X-Origin-URI": "https://evil.com/"}, ""},
		{map[string]string{"X-Host": "wiki.example.com", "X-Forwarded-Proto": "https"}, ""},
	}
	for _, test := range tests {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		for k, v := range test.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%v: got status %d, want %d", test.headers, rec.Code, http.StatusUnauthorized)
		}
		got, err := url.QueryUnescape(rec.Header().Get("X-Login-Redir"))
		if err != nil || got != test.want {
			t.Errorf("%v: got X-Login-Redir for %q, want %q", test.headers, got, test.want)
		}
	}

	// nginx puts the header value in the query as is, the login form must get the URL back
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Origin-URI", uri)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	rec = request(h, http.MethodGet, "/login?redir="+rec.Header().Get("X-Login-Redir"), nil)
	if want := `value="/wiki/page?a=1&amp;b=x%26y"`; !strings.Contains(rec.Body.String(), want) {
		t.Errorf("login form does not contain %s", want)
	}

	// no redirect target for requests with a valid session
	session := login(t, h, "/login")
	req = httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("X-Origin-URI", uri)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Login-Redir") != "" {
		t.Errorf("valid session: got status %d and X-Login-Redir %q, want %d and none", rec.Code, rec.Header().Get("X-Login-Redir"), http.StatusOK)
	}
}

// The templates must not escape values on top of pongo2's autoescaping.
func TestTemplatesEscapeOnce(t *testing.T) {
	h := newTestHandler(t, WebConfig{}, "")
	doubled := regexp.MustCompile(`&amp;(?:amp|lt|gt|quot|#39);`)

	rec := request(h, http.MethodPost, "/login", url.Values{"username": {"alice"}, "password": {"wrong"}, "redirect": {"/x?a=1&b=<c>"}})
	body := rec.Body.String()
	if want := `value="/x?a=1&amp;b=&lt;c&gt;"`; !strings.Contains(body, want) {
		t.Errorf("login form does not contain %s", want)
	}
	if m := doubled.FindString(body); m != "" {
		t.Errorf("login form contains doubly escaped value: %s", m)
	}

	rec = request(h, http.MethodPost, "/login", url.Values{"username": {"o'brien&<co>"}, "password": {"secret"}})
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge > 0 {
			session = c
		}
	}
	if session == nil {
		t.Fatal("login failed")
	}
	rec = request(h, http.MethodGet, "/login", nil, session)
	body = rec.Body.String()
	if want := `o&#39;brien&amp;&lt;co&gt;`; !strings.Contains(body, want) {
		t.Errorf("logged-in page does not contain %s", want)
	}
	if m := doubled.FindString(body); m != "" {
		t.Errorf("logged-in page contains doubly escaped value: %s", m)
	}
}
