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

	"github.com/gin-gonic/gin"
	"github.com/whawty/nginx-sso/ui"
)

const (
	WebAuthPath     = "/auth"
	WebLoginPath    = "/login"
	WebLogoutPath   = "/logout"
	WebUIPathPrefix = "/ui/"
)

func webHandleAuth(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func webHandleLogin(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func webHandleLogout(c *gin.Context) {
	c.Status(http.StatusNotImplemented)
}

func runWeb(listener net.Listener, config *WebConfig) (err error) {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Recovery())
	r.HandleMethodNotAllowed = true

	r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusSeeOther, WebLoginPath) })
	r.StaticFS(WebUIPathPrefix, ui.Assets)
	r.GET(WebAuthPath, webHandleAuth)
	r.GET(WebLoginPath, webHandleLogin)
	r.GET(WebLogoutPath, webHandleLogout)

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

func runWebAddr(addr string, config *WebConfig) (err error) {
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runWeb(ln.(*net.TCPListener), config)
}

func runWebListener(listener *net.TCPListener, config *WebConfig) (err error) {
	return runWeb(listener, config)
}
