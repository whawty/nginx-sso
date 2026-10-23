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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/flosch/pongo2/v6"
	"github.com/gin-gonic/gin"
	"github.com/mileusna/useragent"
	"github.com/oklog/ulid/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/whawty/nginx-sso/auth"
	"github.com/whawty/nginx-sso/cookie"
	"github.com/whawty/nginx-sso/ui"
	"gitlab.com/go-box/pongo2gin/v6"
)

var (
	webRequests        = prometheus.NewCounterVec(prometheus.CounterOpts{Subsystem: "web", Name: "requests_total"}, []string{"status", "endpoint"})
	webRequestDuration = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Subsystem: "web", Name: "request_duration_seconds",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}}, []string{"endpoint"})
)

func promMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		endpoint := path.Base(c.Request.URL.Path)
		now := time.Now()
		c.Next()
		webRequestDuration.WithLabelValues(endpoint).Observe(time.Since(now).Seconds())
		webRequests.WithLabelValues(strconv.Itoa(c.Writer.Status()), endpoint).Inc()
	}
}

type WebError struct {
	Error string `json:"error"`
}

func logTemplateErrors(c *gin.Context) {
	for _, err := range c.Errors {
		wl.Printf("HTML template error: %s", err)
	}
}

func getAgentInfo(c *gin.Context) cookie.AgentInfo {
	ua := useragent.Parse(c.GetHeader("User-Agent"))
	deviceType := "unknown"
	if ua.Mobile {
		deviceType = cookie.DeviceTypeMobile
	} else if ua.Tablet {
		deviceType = cookie.DeviceTypeTablet
	} else if ua.Desktop {
		deviceType = cookie.DeviceTypeDesktop
	} else if ua.Bot {
		deviceType = cookie.DeviceTypeBot
	}
	return cookie.AgentInfo{Name: ua.Name, OS: ua.OS, DeviceType: deviceType}
}

type HandlerContext struct {
	conf    *WebConfig
	cookies *cookie.Store
	auth    auth.Backend
}

func (h *HandlerContext) verifyCookie(c *gin.Context) (*cookie.Session, error) {
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

// relativeRedirect sends a redirect to location without turning it into an
// absolute path like c.Redirect does. All redirects to pages of the web
// interface use paths relative to the current page, so they also work behind
// proxies which strip a path prefix before passing requests on.
func relativeRedirect(c *gin.Context, code int, location string) {
	c.Header("Location", location)
	c.AbortWithStatus(code)
}

func (h *HandlerContext) renderLoggedIn(c *gin.Context, code int, session *cookie.Session, alerts []ui.Alert) {
	tmplCtx := pongo2.Context{"login": h.conf.Login, "session": session}
	if sessions, err := h.cookies.ListUser(session.Username); err == nil {
		tmplCtx["sessions"] = sessions
	} else {
		alerts = append(alerts, ui.Alert{Level: ui.AlertDanger, Heading: "failed to load user sessions", Message: err.Error()})
	}
	tmplCtx["alerts"] = alerts
	c.HTML(http.StatusOK, "logged-in.htmpl", tmplCtx)
	logTemplateErrors(c)
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
	if session, err := h.verifyCookie(c); err == nil {
		h.renderLoggedIn(c, http.StatusOK, session, nil)
		return
	}

	tmplCtx := pongo2.Context{"login": h.conf.Login}
	tmplCtx["redirect"], _ = c.GetQuery("redir")
	c.HTML(http.StatusOK, "login.htmpl", tmplCtx)
	logTemplateErrors(c)
}

func (h *HandlerContext) handleLoginPost(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")
	tmplCtx := pongo2.Context{"login": h.conf.Login, "redirect": redirect}
	if username == "" || password == "" {
		tmplCtx["alert"] = ui.Alert{Level: ui.AlertDanger, Heading: "missing parameter", Message: "username and password are mandatory"}
		c.HTML(http.StatusBadRequest, "login.htmpl", tmplCtx)
		logTemplateErrors(c)
		return
	}

	err := h.auth.Authenticate(username, password)
	if err != nil {
		tmplCtx["alert"] = ui.Alert{Level: ui.AlertDanger, Heading: "login failed", Message: err.Error()}
		c.HTML(http.StatusBadRequest, "login.htmpl", tmplCtx)
		logTemplateErrors(c)
		return
	}

	value, opts, err := h.cookies.New(username, getAgentInfo(c))
	if err != nil {
		tmplCtx["alert"] = ui.Alert{Level: ui.AlertDanger, Heading: "failed to generate cookie", Message: err.Error()}
		c.HTML(http.StatusBadRequest, "login.htmpl", tmplCtx)
		logTemplateErrors(c)
		return
	}
	c.SetCookie(opts.Name, value, opts.MaxAge, "/", opts.Domain, opts.Secure, true)

	if redirect == "" {
		redirect = "login"
	}
	relativeRedirect(c, http.StatusSeeOther, redirect)
}

func (h *HandlerContext) handleLogout(c *gin.Context) {
	session, err := h.verifyCookie(c)
	if err == nil {
		if idParam, _ := c.GetQuery("id"); idParam != "" {
			id, err := ulid.ParseStrict(idParam)
			if err != nil {
				alert := ui.Alert{Level: ui.AlertDanger, Heading: "invalid Session", Message: err.Error()}
				h.renderLoggedIn(c, http.StatusBadRequest, session, []ui.Alert{alert})
				return
			}
			if err = h.cookies.RevokeID(session.Username, id); err != nil {
				alert := ui.Alert{Level: ui.AlertDanger, Heading: "failed to revoke session", Message: err.Error()}
				h.renderLoggedIn(c, http.StatusInternalServerError, session, []ui.Alert{alert})
				return
			}
			h.renderLoggedIn(c, http.StatusOK, session, nil)
			return
		}

		if err = h.cookies.Revoke(*session); err != nil {
			alert := ui.Alert{Level: ui.AlertDanger, Heading: "failed to revoke session", Message: err.Error()}
			h.renderLoggedIn(c, http.StatusInternalServerError, session, []ui.Alert{alert})
			return
		}
	}
	opts := h.cookies.Options()
	c.SetCookie(opts.Name, "invalid", -1, "/", opts.Domain, opts.Secure, true)
	redirect, _ := c.GetQuery("redir")
	if redirect == "" {
		redirect = "login"
	}
	relativeRedirect(c, http.StatusSeeOther, redirect)
}

func (h *HandlerContext) handleSessions(c *gin.Context) {
	session, err := h.verifyCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, WebError{err.Error()})
		return
	}
	sessions, err := h.cookies.ListUser(session.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, WebError{err.Error()})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

func (h *HandlerContext) handleRevocations(c *gin.Context) {
	auth_header := c.GetHeader("Authorization")
	if auth_header == "" {
		c.JSON(http.StatusUnauthorized, WebError{"no authorization header found"})
		return
	}
	auth_parts := strings.SplitN(auth_header, " ", 2)
	if len(auth_parts) != 2 || auth_parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, WebError{"authorization header is invalid"})
		return
	}
	authenticated := false
	for _, token := range h.conf.Revocations.Tokens {
		if token == auth_parts[1] {
			authenticated = true
			break
		}
	}
	if !authenticated {
		c.JSON(http.StatusUnauthorized, WebError{"unauthorized token"})
		return
	}

	revocations, err := h.cookies.ListRevoked()
	if err != nil {
		c.JSON(http.StatusInternalServerError, WebError{err.Error()})
		return
	}
	c.JSON(http.StatusOK, revocations)
}

// normalizeBasePath returns the base path in the form used for the routes:
// empty if the web interface is served at "/", otherwise starting with but
// not ending in a slash.
func normalizeBasePath(p string) string {
	p = path.Clean("/" + strings.TrimSpace(p))
	if p == "/" {
		return ""
	}
	return p
}

// newWebHandler returns the handler for all endpoints of the web interface.
// They are mounted under config.BasePath, i.e. /login becomes
// <base-path>/login. The metrics endpoint is the exception, it uses the path
// configured for it as is.
func newWebHandler(config *WebConfig, prom *MetricsHandler, cookies *cookie.Store, auth auth.Backend) (http.Handler, error) {
	config.BasePath = normalizeBasePath(config.BasePath)
	if strings.ContainsAny(config.BasePath, ":*") {
		// gin would treat these as parameters or wildcards
		return nil, fmt.Errorf("web.base-path must not contain ':' or '*'")
	}
	if config.Login.Title == "" {
		config.Login.Title = "whawty.nginx-sso Login"
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.HandleMethodNotAllowed = true
	// gin would send absolute redirects which don't work behind proxies
	// stripping a path prefix
	r.RedirectTrailingSlash = false

	var htmlTmplLoader pongo2.TemplateLoader
	if config.Login.TemplatesPath != "" {
		var err error
		if htmlTmplLoader, err = pongo2.NewLocalFileSystemLoader(config.Login.TemplatesPath); err != nil {
			return nil, err
		}
	} else {
		htmlTmplLoader = pongo2.NewFSLoader(ui.Assets)
	}
	r.HTMLRender = pongo2gin.New(pongo2gin.RenderOptions{
		TemplateSet: pongo2.NewSet("html", htmlTmplLoader),
		ContentType: "text/html; charset=utf-8"})

	prom.install(r)

	h := &HandlerContext{conf: config, cookies: cookies, auth: auth}
	if config.BasePath != "" {
		// <base-path> -> <base-path>/
		basePathDir := url.PathEscape(path.Base(config.BasePath)) + "/"
		r.GET(config.BasePath, func(c *gin.Context) { relativeRedirect(c, http.StatusSeeOther, basePathDir) })
	}
	base := r.Group(config.BasePath + "/")
	base.GET("/", func(c *gin.Context) { relativeRedirect(c, http.StatusSeeOther, "login") })
	base.StaticFS("/ui/", http.FS(ui.StaticAssets))

	g := base.Group("/")
	if reg := prom.reg(); reg != nil {
		g.Use(promMiddleware())
		if err := reg.Register(webRequests); err != nil {
			return nil, err
		}
		if err := reg.Register(webRequestDuration); err != nil {
			return nil, err
		}
	}
	g.GET("/auth", h.handleAuth)
	g.GET("/login", h.handleLoginGet)
	g.POST("/login", h.handleLoginPost)
	g.GET("/logout", h.handleLogout)
	g.GET("/sessions", h.handleSessions)
	g.GET("/revocations", h.handleRevocations)

	return r, nil
}

func runWeb(config *WebConfig, prom *MetricsHandler, cookies *cookie.Store, auth auth.Backend) (err error) {
	if config.Listen == "" {
		config.Listen = ":http"
	}

	handler, err := newWebHandler(config, prom, cookies, auth)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
	where := "'/'"
	if config.BasePath != "" {
		where = fmt.Sprintf("base path '%s'", config.BasePath)
	}
	server := &http.Server{Handler: handler, WriteTimeout: 60 * time.Second, ReadTimeout: 60 * time.Second}
	if config.TLS != nil {
		server.TLSConfig, err = config.TLS.ToGoTLSConfig()
		if err != nil {
			return
		}
		wl.Printf("web-api: listening on '%s' using TLS, serving %s", listener.Addr(), where)
		return server.ServeTLS(listener, "", "")
	}
	wl.Printf("web-api: listening on '%s', serving %s", listener.Addr(), where)
	return server.Serve(listener)
}
