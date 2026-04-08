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
	"context"
	"fmt"
	"log"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	IssuerURL    string `yaml:"issuer-url"`
	ClientID     string `yaml:"client-id"`
	ClientSecret string `yaml:"client-secret"`
	RedirectURL  string `yaml:"redirect-url"`
}

type OIDCBackend struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	infoLog      *log.Logger
	dbgLog       *log.Logger
}

func NewOIDCBackend(conf *OIDCConfig, prom prometheus.Registerer, infoLog, dbgLog *log.Logger) (Backend, error) {
	b := &OIDCBackend{infoLog: infoLog, dbgLog: dbgLog}
	var err error
	b.provider, err = oidc.NewProvider(context.TODO(), conf.IssuerURL)
	if err != nil {
		return nil, err
	}
	b.verifier = b.provider.Verifier(&oidc.Config{ClientID: conf.ClientID})
	b.oauth2Config = oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		RedirectURL:  conf.RedirectURL,
		Endpoint:     b.provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"}, // TODO: hardcoded scopes...
	}

	if prom != nil {
		err = b.initPrometheus(prom)
		if err != nil {
			return nil, err
		}
	}
	infoLog.Printf("OIDC: successfully initilized using IDP: %s", conf.IssuerURL)
	return b, nil
}

func (b *OIDCBackend) initPrometheus(prom prometheus.Registerer) (err error) {
	return metricsCommon(prom)
}

func (b *OIDCBackend) Authenticate(username, password string) error {
	authRequestsFailed.WithLabelValues().Inc()
	return fmt.Errorf("not yet implemented")
}
