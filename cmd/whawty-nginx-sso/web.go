//
// Copyright (c) 2023 whawty contributors (see AUTHORS file)
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
	"net"
	"net/http"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gin-gonic/gin"
	"github.com/whawty/nginx-sso/auth"
	"github.com/whawty/nginx-sso/cookie"
	"github.com/whawty/nginx-sso/ui"
	"gitlab.com/go-box/pongo2gin/v6"
)

const (
	WebAuthPath     = "/auth"
	WebLoginPath    = "/login"
	WebLogoutPath   = "/logout"
	WebUIPathPrefix = "/ui/"
)

type HandlerContext struct {
	cookies *cookie.Controller
	auth    auth.Backend
}

func (h *HandlerContext) webHandleAuth(c *gin.Context) {
	cookie, err := c.Cookie(h.cookies.Options().Name)
	if err != nil || cookie == "" {
		c.Data(http.StatusUnauthorized, "text/plain", []byte("no cookie found"))
		return
	}

	session, err := h.cookies.Verify(cookie)
	if err != nil {
		c.Data(http.StatusUnauthorized, "text/plain", []byte(err.Error()))
		return
	}
	c.Header("X-Username", session.Username)
	c.Status(http.StatusOK)
}

func (h *HandlerContext) webHandleLogin(c *gin.Context) {
	// TODO: check if cookie already exists and return html with username info and link to logout

	if c.Request.Method == http.MethodGet {
		redirect, _ := c.GetQuery("redir")
		c.HTML(http.StatusOK, "login.htmpl", pongo2.Context{
			"title":    "whawty.nginx-sso Login",
			"uiPrefix": WebUIPathPrefix,
			"redirect": redirect,
		})
		return
	}

	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")
	if username == "" || password == "" {
		// TODO: show login template again (with error message)
		c.Data(http.StatusBadRequest, "text/plain", []byte("Missing at least one of: username, password"))
		return
	}

	err := h.auth.Authenticate(username, password)
	if err != nil {
		// TODO: show login template again (with error message)
		c.Data(http.StatusBadRequest, "text/plain", []byte("login failed: "+err.Error()))
		return
	}

	value, opts, err := h.cookies.Mint(cookie.Payload{Username: "foo"})
	if err != nil {
		// TODO: show login template again (with error message)
		c.Data(http.StatusInternalServerError, "text/plain", []byte("failed to generate cookie: "+err.Error()))
		return
	}
	c.SetCookie(opts.Name, value, opts.MaxAge, "/", opts.Domain, opts.Secure, true)

	if redirect == "" {
		// TODO: show HTML site with username info and link to logout
		c.Data(http.StatusOK, "text/plain", []byte("successfully logged in as: "+username))
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, redirect)
}

func (h *HandlerContext) webHandleLogout(c *gin.Context) {
	opts := h.cookies.Options()
	c.SetCookie(opts.Name, "invalid", -1, "/", opts.Domain, opts.Secure, true)

}

func runWeb(listener net.Listener, config *WebConfig, cookies *cookie.Controller, auth auth.Backend) (err error) {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.HandleMethodNotAllowed = true
	r.HTMLRender = pongo2gin.New(pongo2gin.RenderOptions{
		TemplateSet: pongo2.NewSet("html", pongo2.MustNewHttpFileSystemLoader(ui.Assets, "")),
		ContentType: "text/html; charset=utf-8"})

	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, WebLoginPath) })
	r.StaticFS(WebUIPathPrefix, ui.StaticAssets)

	h := &HandlerContext{cookies: cookies, auth: auth}
	r.GET(WebAuthPath, h.webHandleAuth)
	r.GET(WebLoginPath, h.webHandleLogin)
	r.POST(WebLoginPath, h.webHandleLogin)
	r.GET(WebLogoutPath, h.webHandleLogout)

	server := &http.Server{Handler: r, WriteTimeout: 60 * time.Second, ReadTimeout: 60 * time.Second}
	if config != nil && config.TLS != nil {
		server.TLSConfig, err = config.TLS.ToGoTLSConfig()
		if err != nil {
			return
		}
		wl.Printf("web-api: listening on '%s' using TLS", listener.Addr())
		return server.ServeTLS(listener, "", "")

	}
	wl.Printf("web-api: listening on '%s'", listener.Addr())
	return server.Serve(listener)
}

func runWebAddr(addr string, config *WebConfig, cookies *cookie.Controller, auth auth.Backend) (err error) {
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runWeb(ln.(*net.TCPListener), config, cookies, auth)
}

func runWebListener(listener *net.TCPListener, config *WebConfig, cookies *cookie.Controller, auth auth.Backend) (err error) {
	return runWeb(listener, config, cookies, auth)
}
