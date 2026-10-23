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
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/whawty/nginx-sso/ui"
)

func TestContentSecurityPolicy(t *testing.T) {
	for domain, formAction := range map[string]string{
		"":             "form-action 'self';",
		"example.com":  "form-action 'self' example.com:* *.example.com:*;",
		".Example.COM": "form-action 'self' example.com:* *.example.com:*;",
		"sso-1.a.b.at": "form-action 'self' sso-1.a.b.at:* *.sso-1.a.b.at:*;",
	} {
		csp, err := contentSecurityPolicy(domain)
		if err != nil {
			t.Errorf("cookie domain %q: unexpected error: %v", domain, err)
			continue
		}
		if !strings.Contains(csp, formAction) {
			t.Errorf("cookie domain %q: policy %q does not contain %q", domain, csp, formAction)
		}
		for _, directive := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, directive) {
				t.Errorf("cookie domain %q: policy %q does not contain %q", domain, csp, directive)
			}
		}
	}

	for _, domain := range []string{"exa mple.com", "example.com; script-src *", "*.example.com", "example..com", "-example.com"} {
		if _, err := contentSecurityPolicy(domain); err == nil {
			t.Errorf("cookie domain %q: no error", domain)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newTestHandler(t, WebConfig{BasePath: "/sso"}, "example.com")
	want, _ := contentSecurityPolicy("example.com")
	session := login(t, h, "/sso/login")

	for _, target := range []string{"/sso/login", "/sso/ui/css/main.css", "/sso/auth", "/sso/nonexistent", "/"} {
		for _, cookies := range [][]*http.Cookie{nil, {session}} {
			rec := request(h, http.MethodGet, target, nil, cookies...)
			for header, value := range map[string]string{
				"Content-Security-Policy": want,
				"X-Content-Type-Options":  "nosniff",
				"X-Frame-Options":         "DENY",
				"Referrer-Policy":         "same-origin",
			} {
				if got := rec.Header().Get(header); got != value {
					t.Errorf("GET %s (logged in: %t): got %s %q, want %q", target, cookies != nil, header, got, value)
				}
			}
		}
	}
}

// pages returns the pages of the web interface: the login form, the login
// form after a failed login and the list of sessions with another session.
func pages(t *testing.T) map[string]string {
	t.Helper()
	h := newTestHandler(t, WebConfig{}, "")
	result := map[string]string{}
	result["login form"] = request(h, http.MethodGet, "/login?redir=/x", nil).Body.String()
	failed := url.Values{"username": {"alice"}, "password": {"wrong"}, "redirect": {"/x"}}
	result["failed login"] = request(h, http.MethodPost, "/login", failed).Body.String()
	session := login(t, h, "/login")
	login(t, h, "/login")
	result["sessions"] = request(h, http.MethodGet, "/login", nil, session).Body.String()
	return result
}

// The Content-Security-Policy does not allow inline scripts and styles.
func TestTemplatesHaveNoInlineCode(t *testing.T) {
	scriptTag := regexp.MustCompile(`(?is)<script\b[^>]*>`)
	scriptSrc := regexp.MustCompile(`(?is)\ssrc\s*=`)
	inline := map[string]*regexp.Regexp{
		"style element":   regexp.MustCompile(`(?i)<style\b`),
		"style attribute": regexp.MustCompile(`(?i)\sstyle\s*=`),
		"event handler":   regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
		"javascript: URL": regexp.MustCompile(`(?i)javascript:`),
	}
	for name, page := range pages(t) {
		for what, re := range inline {
			if m := re.FindString(page); m != "" {
				t.Errorf("%s: contains %s: %s", name, what, m)
			}
		}
		for _, tag := range scriptTag.FindAllString(page, -1) {
			if !scriptSrc.MatchString(tag) {
				t.Errorf("%s: contains inline script: %s", name, tag)
			}
		}
	}
}

// All files the pages reference must be part of the web interface, so it
// works without internet access and with the Content-Security-Policy.
func TestUIAssetsAreSelfContained(t *testing.T) {
	exists := func(name string) bool {
		_, err := fs.Stat(ui.StaticAssets, name)
		return err == nil
	}

	attr := regexp.MustCompile(`(?i)\s(src|href|action)\s*=\s*"([^"]*)"`)
	for name, page := range pages(t) {
		for _, m := range attr.FindAllStringSubmatch(page, -1) {
			kind, target := strings.ToLower(m[1]), m[2]
			switch {
			case kind == "action":
				if target != "login" && target != "logout" {
					t.Errorf("%s: form action %q is not an endpoint of the web interface", name, target)
				}
			case strings.HasPrefix(target, "ui/"):
				if !exists(strings.TrimPrefix(target, "ui/")) {
					t.Errorf("%s: %s %q does not exist", name, kind, target)
				}
			default:
				t.Errorf("%s: %s %q is not a file of the web interface", name, kind, target)
			}
		}
	}

	cssURL := regexp.MustCompile(`url\(\s*("[^"]*"|'[^']*'|[^)'"\s]*)\s*\)`)
	absoluteURL := regexp.MustCompile(`https?://`)
	err := fs.WalkDir(ui.StaticAssets, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(name) == ".htmpl" { // templates are not served
			return err
		}
		content, err := fs.ReadFile(ui.StaticAssets, name)
		if err != nil {
			return err
		}
		switch path.Ext(name) {
		case ".css":
			for _, m := range cssURL.FindAllStringSubmatch(string(content), -1) {
				target := strings.Trim(m[1], `"'`)
				if strings.HasPrefix(target, "data:") {
					continue
				}
				if u, err := url.Parse(target); err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/") {
					t.Errorf("%s: url(%s) is not relative", name, target)
				} else if !exists(path.Join(path.Dir(name), u.Path)) {
					t.Errorf("%s: url(%s) does not exist", name, target)
				}
			}
		case ".js":
			// the vendored scripts mention URLs in comments and messages
			if !strings.HasPrefix(name, "bootstrap/") {
				if m := absoluteURL.FindString(string(content)); m != "" {
					t.Errorf("%s: contains absolute URL", name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
