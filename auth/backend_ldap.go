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
	"log"
	//	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	Server            string `yaml:"server"`
	RootDN            string `yaml:"root_dn"`
	ManagerDN         string `yaml:"manager_dn"`
	ManagerPassword   string `yaml:"manager_password"`
	UserSearchBase    string `yaml:"user_search_base"`
	UserSearchFilter  string `yaml:"user_search_filter"`
	UsernameAttribute string `yaml:"username_attribute"`
	// TODO: TLS
}

type LDAPBackend struct {
	conf    *LDAPConfig
	infoLog *log.Logger
	dbgLog  *log.Logger
}

func NewLDAPBackend(conf *LDAPConfig, infoLog, dbgLog *log.Logger) (Backend, error) {
	if conf.UserSearchBase == "" {
		conf.UserSearchBase = conf.RootDN
	}
	if conf.UserSearchFilter == "" {
		conf.UserSearchFilter = "(&(inetOrgPerson)(uid={0}))"
	}
	if conf.UsernameAttribute == "" {
		conf.UsernameAttribute = "uid"
	}

	b := &LDAPBackend{conf: conf, infoLog: infoLog, dbgLog: dbgLog}
	infoLog.Printf("ldap: successfully intialized")
	return b, nil
}

func (w *LDAPBackend) Authenticate(username, password string) error {
	// TODO: implement this: https://pkg.go.dev/gopkg.in/ldap.v3#example-package-UserAuthentication
	return fmt.Errorf("not yet implemented")
}
