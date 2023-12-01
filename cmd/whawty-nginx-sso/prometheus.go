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

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsHandler struct {
	registry *prometheus.Registry
	listener net.Listener
	path     string
}

func newMetricsHandler(config *PrometheusConfig) (m *MetricsHandler, err error) {
	m = &MetricsHandler{}
	if config == nil {
		return
	}
	m.registry = prometheus.NewRegistry()
	m.path = "/metrics"
	if config.Path != "" {
		m.path = config.Path
	}
	if config.Listen != "" {
		m.listener, err = net.Listen("tcp", config.Listen)
		if err != nil {
			return
		}
		wl.Printf("prometheus: listening on '%s'", config.Listen)
	}

	m.registry.MustRegister(collectors.NewBuildInfoCollector())
	return
}

func (m *MetricsHandler) install(r *gin.Engine) {
	if m.registry == nil || m.listener != nil {
		return
	}
	r.GET(m.path, gin.WrapH(promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})))
}

func (m *MetricsHandler) run() {
	if m.registry == nil || m.listener == nil {
		return
	}

	mux := http.NewServeMux()
	mux.Handle(m.path, promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	srv := &http.Server{Handler: mux}
	err := srv.Serve(m.listener)
	wl.Printf("prometheus: listener thread has stopped (err=%v)", err)
}
