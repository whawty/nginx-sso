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
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/whawty/auth/store"
)

const (
	MaxConcurrentRemoteUpgrades = 10
)

type WhawtyAuthConfig struct {
	ConfigFile       string `yaml:"store"`
	RemoteUpgradeUrl string `yaml:"remote-upgrade-url"`
}

type WhawtyAuthBackend struct {
	store       *store.Dir
	upgradeChan chan whawtyUpgradeRequest
	infoLog     *log.Logger
	dbgLog      *log.Logger
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
	if conf.RemoteUpgradeUrl != "" {
		err = b.runRemoteUpgrader(conf.RemoteUpgradeUrl)
		if err != nil {
			return nil, err
		}
	}
	infoLog.Printf("whawty-auth: successfully intialized store at %s (%d parameter-sets loaded)", s.BaseDir, len(s.Params))
	return b, nil
}

type whawtyUpgradeRequest struct {
	Session     string `json:"session,omitempty"`
	Username    string `json:"username"`
	OldPassword string `json:"oldpassword,omitempty"`
	NewPassword string `json:"newpassword,omitempty"`
}

func remoteHTTPUpgrade(upgrade whawtyUpgradeRequest, remote string, infoLog, dbgLog *log.Logger) {
	reqdata, err := json.Marshal(upgrade)
	if err != nil {
		infoLog.Printf("whawty-auth: error while encoding remote-upgrade request: %v", err)
		return
	}
	req, _ := http.NewRequest("POST", remote, bytes.NewReader(reqdata))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		infoLog.Printf("whawty-auth: error sending remote-upgrade request: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		infoLog.Printf("whawty-auth: remote-upgrade: failed for '%s' with status: %s", upgrade.Username, resp.Status)
	} else {
		dbgLog.Printf("whawty-auth: successfully upgraded '%s'", upgrade.Username)
	}
}

func remoteHTTPUpgrader(upgradeChan <-chan whawtyUpgradeRequest, remote string, infoLog, dbgLog *log.Logger) {
	sem := make(chan bool, MaxConcurrentRemoteUpgrades)
	for upgrade := range upgradeChan {
		select {
		case sem <- true:
			dbgLog.Printf("whawty-auth: upgrading '%s' via %s", upgrade.Username, remote)
			go func(upgrade whawtyUpgradeRequest, remote string) {
				defer func() { <-sem }()
				remoteHTTPUpgrade(upgrade, remote, infoLog, dbgLog)
			}(upgrade, remote)
		default:
			dbgLog.Printf("whawty-auth: ignoring upgrade request for '%s' due to rate-limiting", upgrade.Username)
		}
	}
}

func (b *WhawtyAuthBackend) runRemoteUpgrader(remote string) error {
	r, err := url.Parse(remote)
	if err != nil {
		return err
	}
	switch r.Scheme {
	case "http":
		b.infoLog.Printf("whaty: using insecure url for remote upgrades: %s", remote)
		fallthrough
	case "https":
		b.upgradeChan = make(chan whawtyUpgradeRequest, 10)
		go remoteHTTPUpgrader(b.upgradeChan, remote, b.infoLog, b.dbgLog)
	default:
		return fmt.Errorf("whawty-auth: invalid upgrade url: %s", remote)
	}
	return nil
}

func (b *WhawtyAuthBackend) Authenticate(username, password string) error {
	ok, _, upgradeable, _, err := b.store.Authenticate(username, password)
	if ok && upgradeable && b.upgradeChan != nil {
		select {
		case b.upgradeChan <- whawtyUpgradeRequest{Username: username, OldPassword: password}:
		default: // remote upgrades are opportunistic
		}
	}
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("invalid username or password")
	}
	return nil
}
