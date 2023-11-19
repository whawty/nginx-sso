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
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/spreadspace/tlsconfig"
)

type LDAPConfig struct {
	Servers          []string             `yaml:"servers"`
	RootDN           string               `yaml:"root-dn"`
	ManagerDN        string               `yaml:"manager-dn"`
	ManagerPassword  string               `yaml:"manager-password"`
	UserSearchBase   string               `yaml:"user-search-base"`
	UserSearchFilter string               `yaml:"user-search-filter"`
	UserDNTemplate   string               `yaml:"user-dn-template"`
	StartTLS         bool                 `yaml:"start-tls"`
	TLS              *tlsconfig.TLSConfig `yaml:"tls"`
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
		var err error
		if b.tlsConf, err = conf.TLS.ToGoTLSConfig(); err != nil {
			return nil, fmt.Errorf("ldap: %v", err)
		}
	}
	infoLog.Printf("ldap: successfully initialized")
	return b, nil
}

func (b *LDAPBackend) getUserDN(l *ldap.Conn, username string) (string, bool, error) {
	if b.conf.UserDNTemplate != "" {
		userdn := strings.NewReplacer("{0}", ldap.EscapeDN(username)).Replace(b.conf.UserDNTemplate)
		return userdn, false, nil
	}

	if b.conf.ManagerDN != "" && b.conf.ManagerPassword != "" {
		if err := l.Bind(b.conf.ManagerDN, b.conf.ManagerPassword); err != nil {
			return "", true, err
		}
	}

	f := strings.NewReplacer("{0}", ldap.EscapeFilter(username)).Replace(b.conf.UserSearchFilter)
	searchRequest := ldap.NewSearchRequest(b.conf.UserSearchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, f, []string{"dn"}, nil)
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

func (b *LDAPBackend) authenticate(server, username, password string) (bool, error) {
	opts := []ldap.DialOpt{}
	srvTLSConf := &tls.Config{}

	if b.conf.TLS != nil {
		sn, err := serverNameFromUrl(server)
		if err != nil {
			return true, err
		}
		srvTLSConf = b.tlsConf.Clone()
		srvTLSConf.ServerName = sn
		if b.conf.StartTLS == false {
			opts = append(opts, ldap.DialWithTLSConfig(srvTLSConf))
		}
	}

	l, err := ldap.DialURL(server, opts...)
	if err != nil {
		return true, err
	}
	defer l.Close()

	if srvTLSConf != nil && b.conf.StartTLS {
		if err = l.StartTLS(srvTLSConf); err != nil {
			return true, err
		}
	}

	userdn, retry, err := b.getUserDN(l, username)
	if err != nil {
		return retry, err
	}
	if err = l.Bind(userdn, password); err != nil {
		return false, err
	}
	return false, nil
}

func (b *LDAPBackend) Authenticate(username, password string) (err error) {
	// make sure we don't trigger this: https://github.com/go-ldap/ldap/issues/93
	if username == "" || password == "" {
		return fmt.Errorf("username and or password must not be empty")
	}

	retry := false
	last := b.conf.Servers[0]
	for _, server := range b.conf.Servers {
		if err != nil {
			b.dbgLog.Printf("ldap: login to server '%s' failed: %v ... trying another server", last, err)
		}
		retry, err = b.authenticate(server, username, password)
		if !retry {
			break
		}
		last = server
	}
	return err
}
