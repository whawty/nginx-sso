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

package auth

import (
	"fmt"
	"io"
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsSubsystem = "auth"
)

var (
	authRequests        = prometheus.NewCounterVec(prometheus.CounterOpts{Subsystem: metricsSubsystem, Name: "requests_total"}, []string{"result"})
	authRequestsSuccess = authRequests.MustCurryWith(prometheus.Labels{"result": "success"})
	authRequestsFailed  = authRequests.MustCurryWith(prometheus.Labels{"result": "failed"})
)

type Config struct {
	LDAP   *LDAPConfig       `yaml:"ldap"`
	Static *StaticConfig     `yaml:"static"`
	Whawty *WhawtyAuthConfig `yaml:"whawty"`
}

type Backend interface {
	Authenticate(username, password string) error
}

type NullBackend struct {
}

func (b *NullBackend) Authenticate(username, password string) error {
	return fmt.Errorf("invalid username/password")
}

func metricsCommon(prom prometheus.Registerer) (err error) {
	if err = prom.Register(authRequests); err != nil {
		return
	}
	authRequestsSuccess.WithLabelValues()
	authRequestsFailed.WithLabelValues()
	return nil
}

func NewBackend(conf *Config, prom prometheus.Registerer, infoLog, dbgLog *log.Logger) (Backend, error) {
	if infoLog == nil {
		infoLog = log.New(io.Discard, "", 0)
	}
	if dbgLog == nil {
		dbgLog = log.New(io.Discard, "", 0)
	}

	if conf.LDAP != nil {
		return NewLDAPBackend(conf.LDAP, prom, infoLog, dbgLog)
	}
	if conf.Static != nil {
		return NewStaticBackend(conf.Static, prom, infoLog, dbgLog)
	}
	if conf.Whawty != nil {
		return NewWhawtyAuthBackend(conf.Whawty, prom, infoLog, dbgLog)
	}
	infoLog.Printf("auth: no valid backend configuration found - this instance will only verify cookies")
	return &NullBackend{}, nil
}
