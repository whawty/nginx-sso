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

	"github.com/whawty/auth/store"
)

type WhawtyAuthConfig struct {
	ConfigFile string `yaml:"store"`
}

type WhawtyAuthBackend struct {
	store   *store.Dir
	infoLog *log.Logger
	dbgLog  *log.Logger
}

func NewWhawtyAuthBackend(conf *WhawtyAuthConfig, infoLog, dbgLog *log.Logger) (Backend, error) {
	s, err := store.NewDirFromConfig(conf.ConfigFile)
	if err != nil {
		infoLog.Printf("whawty-auth: failed to intialize store: %v", err)
		return nil, err
	}
	if err = s.Check(); err != nil {
		infoLog.Printf("whawty-auth: failed to intialize store: %v", err)
		return nil, err
	}

	b := &WhawtyAuthBackend{store: s, infoLog: infoLog, dbgLog: dbgLog}
	infoLog.Printf("whawty-auth: successfully intialized store at %s (%d parameter-sets loaded)", s.BaseDir, len(s.Params))
	return b, nil
}

func (w *WhawtyAuthBackend) Authenticate(username, password string) error {
	ok, _, upgradeable, _, err := w.store.Authenticate(username, password)
	if upgradeable {
		w.dbgLog.Printf("whawty-auth: password-hash for user '%s' is upgradable, but upgrades are not implemented yet!", username)
	}
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("invalid username or password")
	}
	return nil
}
