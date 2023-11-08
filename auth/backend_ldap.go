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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	Servers          []string `yaml:"servers"`
	RootDN           string   `yaml:"root-dn"`
	ManagerDN        string   `yaml:"manager-dn"`
	ManagerPassword  string   `yaml:"manager-password"`
	UserSearchBase   string   `yaml:"user-search-base"`
	UserSearchFilter string   `yaml:"user-search-filter"`
	UserDNTemplate   string   `yaml:"user-dn-template"`
	TLS              *struct {
		StartTLS           bool     `yaml:"start-tls"`
		InsecureSkipVerify bool     `yaml:"insecure-skip-verify"`
		CACertificates     []string `yaml:"ca-certificates"`
	} `yaml:"tls"`
}

type LDAPBackend struct {
	conf    *LDAPConfig
	tlsConf *tls.Config
	infoLog *log.Logger
	dbgLog  *log.Logger
}

func NewLDAPBackend(conf *LDAPConfig, infoLog, dbgLog *log.Logger) (Backend, error) {
	if conf.UserSearchBase == "" {
		conf.UserSearchBase = conf.RootDN
	}
	if conf.UserSearchFilter == "" {
		conf.UserSearchFilter = "(&(objectClass=inetOrgPerson)(uid={0}))"
	}
	if len(conf.Servers) == 0 {
		return nil, fmt.Errorf("ldap: at least server must be configured")
	}

	b := &LDAPBackend{conf: conf, infoLog: infoLog, dbgLog: dbgLog}
	if conf.TLS != nil {
		if err := b.initTLSConfig(); err != nil {
			return nil, err
		}
	}
	infoLog.Printf("ldap: successfully initialized")
	return b, nil
}

func loadFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

func serverNameFromUrl(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("server url '%s' is invalid", server)
	}
	return u.Hostname(), nil
}

func (w *LDAPBackend) initTLSConfig() error {
	w.tlsConf = &tls.Config{}
	w.tlsConf.InsecureSkipVerify = w.conf.TLS.InsecureSkipVerify
	w.tlsConf.RootCAs = x509.NewCertPool()
	for _, cert := range w.conf.TLS.CACertificates {
		pemData, err := loadFile(cert)
		if err != nil {
			return fmt.Errorf("ldap: loading ca-certificates failed: %v", err)
		}

		ok := w.tlsConf.RootCAs.AppendCertsFromPEM(pemData)
		if !ok {
			return fmt.Errorf("ldap: no certificates found in file '%s'", cert)
		}
	}
	return nil
}

func (w *LDAPBackend) getUserDN(l *ldap.Conn, username string) (string, bool, error) {
	if w.conf.UserDNTemplate != "" {
		userdn := strings.NewReplacer("{0}", ldap.EscapeDN(username)).Replace(w.conf.UserDNTemplate)
		return userdn, false, nil
	}

	if w.conf.ManagerDN != "" && w.conf.ManagerPassword != "" {
		if err := l.Bind(w.conf.ManagerDN, w.conf.ManagerPassword); err != nil {
			return "", true, err
		}
	}

	f := strings.NewReplacer("{0}", ldap.EscapeFilter(username)).Replace(w.conf.UserSearchFilter)
	searchRequest := ldap.NewSearchRequest(w.conf.UserSearchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, f, []string{"dn"}, nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return "", true, err
	}
	if len(sr.Entries) == 0 {
		return "", false, fmt.Errorf("user not found")
	}
	if len(sr.Entries) > 1 {
		return "", false, fmt.Errorf("user search filter returned multiple results")
	}
	return sr.Entries[0].DN, false, nil
}

func (w *LDAPBackend) authenticate(server, username, password string) (bool, error) {
	opts := []ldap.DialOpt{}
	srvTLSConf := &tls.Config{}

	if w.conf.TLS != nil {
		sn, err := serverNameFromUrl(server)
		if err != nil {
			return true, err
		}
		srvTLSConf = w.tlsConf.Clone()
		srvTLSConf.ServerName = sn
		if w.conf.TLS.StartTLS == false {
			opts = append(opts, ldap.DialWithTLSConfig(srvTLSConf))
		}
	}

	l, err := ldap.DialURL(server, opts...)
	if err != nil {
		return true, err
	}
	defer l.Close()

	if srvTLSConf != nil && w.conf.TLS.StartTLS {
		if err = l.StartTLS(srvTLSConf); err != nil {
			return true, err
		}
	}

	userdn, retry, err := w.getUserDN(l, username)
	if err != nil {
		return retry, err
	}
	if err = l.Bind(userdn, password); err != nil {
		return false, err
	}
	return false, nil
}

func (w *LDAPBackend) Authenticate(username, password string) (err error) {
	// make sure we don't trigger this: https://github.com/go-ldap/ldap/issues/93
	if username == "" || password == "" {
		return fmt.Errorf("username and or password must not be empty")
	}

	retry := false
	last := w.conf.Servers[0]
	for _, server := range w.conf.Servers {
		if err != nil {
			w.dbgLog.Printf("ldap: login to server '%s' failed: %v ... trying another server", last, err)
		}
		retry, err = w.authenticate(server, username, password)
		if !retry {
			break
		}
		last = server
	}
	return err
}
