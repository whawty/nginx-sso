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
	"errors"
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
	conf    *WebConfig
	cookies *cookie.Controller
	auth    auth.Backend
}

func (h *HandlerContext) webVerifyCookie(c *gin.Context) (*cookie.Payload, error) {
	cookie, err := c.Cookie(h.cookies.Options().Name)
	if err != nil {
		return nil, err
	}
	if cookie == "" {
		return nil, errors.New("no cookie found")
	}
	session, err := h.cookies.Verify(cookie)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (h *HandlerContext) webHandleAuth(c *gin.Context) {
	session, err := h.webVerifyCookie(c)
	if err != nil {
		c.Data(http.StatusUnauthorized, "text/plain", []byte(err.Error()))
		return
	}
	c.Header("X-Username", session.Username)
	c.Status(http.StatusOK)
}

func (h *HandlerContext) webHandleLoginGet(c *gin.Context) {
	session, err := h.webVerifyCookie(c)
	if err == nil && session != nil {
		// TODO: follow redir?
		c.HTML(http.StatusOK, "logged-in.htmpl", pongo2.Context{
			"login":    h.conf.Login,
			"username": session.Username,
			"expires":  time.Unix(session.Expires, 0),
		})
		return
	}

	redirect, _ := c.GetQuery("redir")
	c.HTML(http.StatusOK, "login.htmpl", pongo2.Context{
		"login":    h.conf.Login,
		"redirect": redirect,
	})
	return
}

func (h *HandlerContext) webHandleLoginPost(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")
	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.htmpl", pongo2.Context{
			"login":    h.conf.Login,
			"redirect": redirect,
			"alert":    ui.Alert{Level: ui.AlertDanger, Heading: "missing parameter", Message: "username and password are mandatory"},
		})
		return
	}

	err := h.auth.Authenticate(username, password)
	if err != nil {
		c.HTML(http.StatusBadRequest, "login.htmpl", pongo2.Context{
			"login":    h.conf.Login,
			"redirect": redirect,
			"alert":    ui.Alert{Level: ui.AlertDanger, Heading: "login failed", Message: err.Error()},
		})
		return
	}

	value, opts, err := h.cookies.Mint(cookie.Payload{Username: username})
	if err != nil {
		c.HTML(http.StatusBadRequest, "login.htmpl", pongo2.Context{
			"login":    h.conf.Login,
			"redirect": redirect,
			"alert":    ui.Alert{Level: ui.AlertDanger, Heading: "failed to generate cookie", Message: err.Error()},
		})
		return
	}
	c.SetCookie(opts.Name, value, opts.MaxAge, "/", opts.Domain, opts.Secure, true)

	if redirect == "" {
		c.HTML(http.StatusOK, "logged-in.htmpl", pongo2.Context{
			"login":    h.conf.Login,
			"username": username,
			"expires":  time.Now().Add(time.Duration(opts.MaxAge) * time.Second),
		})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, redirect)
}

func (h *HandlerContext) webHandleLogout(c *gin.Context) {
	opts := h.cookies.Options()
	c.SetCookie(opts.Name, "invalid", -1, "/", opts.Domain, opts.Secure, true)
	c.Redirect(http.StatusSeeOther, WebLoginPath) // TODO follow redir??
}

func runWeb(listener net.Listener, config *WebConfig, cookies *cookie.Controller, auth auth.Backend) (err error) {
	if config.Login.Title == "" {
		config.Login.Title = "whawty.nginx-sso Login"
	}
	if config.Login.UIPath == "" {
		config.Login.UIPath = WebUIPathPrefix
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.HandleMethodNotAllowed = true

	var htmlTmplLoader pongo2.TemplateLoader
	if config.Login.TemplatesPath != "" {
		htmlTmplLoader, err = pongo2.NewLocalFileSystemLoader(config.Login.TemplatesPath)
		if err != nil {
			return
		}
	} else {
		htmlTmplLoader = pongo2.MustNewHttpFileSystemLoader(ui.Assets, "")
	}
	r.HTMLRender = pongo2gin.New(pongo2gin.RenderOptions{
		TemplateSet: pongo2.NewSet("html", htmlTmplLoader),
		ContentType: "text/html; charset=utf-8"})

	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, WebLoginPath) })
	r.StaticFS(WebUIPathPrefix, ui.StaticAssets)

	h := &HandlerContext{conf: config, cookies: cookies, auth: auth}
	r.GET(WebAuthPath, h.webHandleAuth)
	r.GET(WebLoginPath, h.webHandleLoginGet)
	r.POST(WebLoginPath, h.webHandleLoginPost)
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
