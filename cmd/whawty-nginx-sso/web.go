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
	"path"
	"strings"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gin-gonic/gin"
	"github.com/whawty/nginx-sso/auth"
	"github.com/whawty/nginx-sso/cookie"
	"github.com/whawty/nginx-sso/ui"
	"gitlab.com/go-box/pongo2gin/v6"
)

type HandlerContext struct {
	conf    *WebConfig
	cookies *cookie.Controller
	auth    auth.Backend
}

func (h *HandlerContext) verifyCookie(c *gin.Context) (*cookie.Payload, error) {
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

func (h *HandlerContext) getBasePath(c *gin.Context) string {
	if h.conf.Login.BasePath != "" {
		return strings.TrimRight(h.conf.Login.BasePath, "/")
	}
	hdr := c.GetHeader("X-BasePath")
	if hdr != "" {
		return strings.TrimRight(hdr, "/")
	}
	return ""
}

func (h *HandlerContext) handleAuth(c *gin.Context) {
	session, err := h.verifyCookie(c)
	if err != nil {
		c.Data(http.StatusUnauthorized, "text/plain", []byte(err.Error()))
		return
	}
	c.Header("X-Username", session.Username)
	c.Status(http.StatusOK)
}

func (h *HandlerContext) handleLoginGet(c *gin.Context) {
	login := h.conf.Login
	login.BasePath = h.getBasePath(c)

	session, err := h.verifyCookie(c)
	if err == nil && session != nil {
		// TODO: follow redir?
		c.HTML(http.StatusOK, "logged-in.htmpl", pongo2.Context{
			"login":    login,
			"username": session.Username,
			"expires":  time.Unix(session.Expires, 0),
		})
		return
	}

	redirect, _ := c.GetQuery("redir")
	c.HTML(http.StatusOK, "login.htmpl", pongo2.Context{
		"login":    login,
		"redirect": redirect,
	})
	return
}

func (h *HandlerContext) handleLoginPost(c *gin.Context) {
	login := h.conf.Login
	login.BasePath = h.getBasePath(c)

	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")
	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.htmpl", pongo2.Context{
			"login":    login,
			"redirect": redirect,
			"alert":    ui.Alert{Level: ui.AlertDanger, Heading: "missing parameter", Message: "username and password are mandatory"},
		})
		return
	}

	err := h.auth.Authenticate(username, password)
	if err != nil {
		c.HTML(http.StatusBadRequest, "login.htmpl", pongo2.Context{
			"login":    login,
			"redirect": redirect,
			"alert":    ui.Alert{Level: ui.AlertDanger, Heading: "login failed", Message: err.Error()},
		})
		return
	}

	value, opts, err := h.cookies.Mint(cookie.Payload{Username: username})
	if err != nil {
		c.HTML(http.StatusBadRequest, "login.htmpl", pongo2.Context{
			"login":    login,
			"redirect": redirect,
			"alert":    ui.Alert{Level: ui.AlertDanger, Heading: "failed to generate cookie", Message: err.Error()},
		})
		return
	}
	c.SetCookie(opts.Name, value, opts.MaxAge, "/", opts.Domain, opts.Secure, true)

	if redirect == "" {
		c.HTML(http.StatusOK, "logged-in.htmpl", pongo2.Context{
			"login":    login,
			"username": username,
			"expires":  time.Now().Add(time.Duration(opts.MaxAge) * time.Second),
		})
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, redirect)
}

func (h *HandlerContext) handleLogout(c *gin.Context) {
	opts := h.cookies.Options()
	c.SetCookie(opts.Name, "invalid", -1, "/", opts.Domain, opts.Secure, true)
	redirect, _ := c.GetQuery("redir")
	if redirect == "" {
		redirect = path.Join(h.getBasePath(c), "login")
	}
	c.Redirect(http.StatusSeeOther, redirect)
}

func runWeb(config *WebConfig, cookies *cookie.Controller, auth auth.Backend) (err error) {
	if config.Listen == "" {
		config.Listen = ":http"
	}
	if config.Login.Title == "" {
		config.Login.Title = "whawty.nginx-sso Login"
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

	h := &HandlerContext{conf: config, cookies: cookies, auth: auth}
	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, path.Join(h.getBasePath(c), "login")) })
	r.StaticFS("/ui/", ui.StaticAssets)
	r.GET("/auth", h.handleAuth)
	r.GET("/login", h.handleLoginGet)
	r.POST("/login", h.handleLoginPost)
	r.GET("/logout", h.handleLogout)

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
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
