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
	"fmt"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var validHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// contentSecurityPolicy returns the Content-Security-Policy of the web
// interface. The pages may only load styles and images (the icons) from the
// web interface itself and must not be embedded by other sites. They don't
// use scripts, so default-src 'none' forbids them like everything else not
// allowed explicitly.
//
// Browsers also apply form-action to the redirect after a form post. After
// logging in users are sent on to the hosts which get the session cookie (see
// isSafeRedirect), so the cookie domain and its subdomains are allowed there
// as well.
func contentSecurityPolicy(cookieDomain string) (string, error) {
	formAction := "'self'"
	if domain := strings.ToLower(strings.TrimPrefix(cookieDomain, ".")); domain != "" {
		if !validHostname.MatchString(domain) {
			return "", fmt.Errorf("cookie domain '%s' is not a valid host name", cookieDomain)
		}
		// without scheme these match the scheme of the page and https if that's http
		formAction += " " + domain + ":* *." + domain + ":*"
	}
	return strings.Join([]string{
		"default-src 'none'",
		"style-src 'self'",
		"img-src 'self'",
		"form-action " + formAction,
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; "), nil
}

// securityHeaders sets the Content-Security-Policy csp and other headers which
// limit what browsers do with the responses.
func securityHeaders(csp string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Not no-referrer: then browsers send "Origin: null" with form posts,
		// which crossOriginProtection rejects in browsers that don't send
		// Sec-Fetch-Site. same-origin still sends no referrer to other sites.
		h.Set("Referrer-Policy", "same-origin")
		c.Next()
	}
}
