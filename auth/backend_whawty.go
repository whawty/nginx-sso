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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spreadspace/tlsconfig"
	"github.com/whawty/auth/store"
)

const (
	MaxConcurrentRemoteUpgrades = 10
)

type WhawtyAuthConfig struct {
	ConfigFile     string `yaml:"store"`
	AutoReload     bool   `yaml:"autoreload"`
	RemoteUpgrades *struct {
		URL      string               `yaml:"url"`
		HTTPHost string               `yaml:"http-host"`
		TLS      *tlsconfig.TLSConfig `yaml:"tls"`
	} `yaml:"remote-upgrades"`
}

type WhawtyAuthBackend struct {
	store           *store.Dir
	storeMutex      sync.RWMutex
	upgradeChan     chan whawtyUpgradeRequest
	upgradeHTTPHost string
	upgradeTLSConf  *tls.Config
	infoLog         *log.Logger
	dbgLog          *log.Logger
}

func NewWhawtyAuthBackend(conf *WhawtyAuthConfig, prom prometheus.Registerer, infoLog, dbgLog *log.Logger) (Backend, error) {
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
	if conf.RemoteUpgrades != nil {
		if conf.RemoteUpgrades.TLS != nil {
			if b.upgradeTLSConf, err = conf.RemoteUpgrades.TLS.ToGoTLSConfig(); err != nil {
				return nil, fmt.Errorf("whawty-auth: remote-upgrade: %v", err)
			}
		}
		b.upgradeHTTPHost = conf.RemoteUpgrades.HTTPHost
		err = b.runRemoteUpgrader(conf.RemoteUpgrades.URL)
		if err != nil {
			return nil, err
		}
	}
	if conf.AutoReload {
		runFileWatcher([]string{conf.ConfigFile}, b.watchFileErrorCB, b.watchFileEventCB)
	}
	if prom != nil {
		err = b.initPrometheus(prom)
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

func remoteHTTPUpgrade(upgrade whawtyUpgradeRequest, remote, httpHost string, client *http.Client, infoLog, dbgLog *log.Logger) {
	reqdata, err := json.Marshal(upgrade)
	if err != nil {
		infoLog.Printf("whawty-auth: error while encoding remote-upgrade request: %v", err)
		return
	}
	req, _ := http.NewRequest("POST", remote, bytes.NewReader(reqdata))
	req.Host = httpHost
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
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

func remoteHTTPUpgrader(upgradeChan <-chan whawtyUpgradeRequest, remote, httpHost string, client *http.Client, infoLog, dbgLog *log.Logger) {
	sem := make(chan bool, MaxConcurrentRemoteUpgrades)
	for upgrade := range upgradeChan {
		select {
		case sem <- true:
			dbgLog.Printf("whawty-auth: upgrading '%s' via %s", upgrade.Username, remote)
			go func(upgrade whawtyUpgradeRequest, remote string) {
				defer func() { <-sem }()
				remoteHTTPUpgrade(upgrade, remote, httpHost, client, infoLog, dbgLog)
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

	b.upgradeChan = make(chan whawtyUpgradeRequest, 10)
	httpClient := &http.Client{}

	switch r.Scheme {
	case "http":
		b.infoLog.Printf("whawty-auth: using insecure url for remote upgrades: %s", remote)
	case "https":
		if b.upgradeTLSConf != nil {
			httpClient.Transport = &http.Transport{TLSClientConfig: b.upgradeTLSConf}
			if b.upgradeTLSConf.InsecureSkipVerify {
				b.infoLog.Printf("whawty-auth: certificate checks for remote upgrades are disabled!")
			}
		}
	default:
		return fmt.Errorf("whawty-auth: invalid upgrade url: %s", remote)
	}
	go remoteHTTPUpgrader(b.upgradeChan, remote, b.upgradeHTTPHost, httpClient, b.infoLog, b.dbgLog)
	return nil
}

func (b *WhawtyAuthBackend) watchFileErrorCB(err error) {
	b.infoLog.Printf("whawty-auth: got error from fsnotify watcher: %v", err)
}

func (b *WhawtyAuthBackend) watchFileEventCB(event fsnotify.Event) {
	newdir, err := store.NewDirFromConfig(event.Name)
	if err != nil {
		b.infoLog.Printf("whawty-auth: reloading store failed: %v, keeping current configuration", err)
		return
	}
	if err := newdir.Check(); err != nil {
		b.infoLog.Printf("whawty-auth: reloading store failed: %v, keeping current configuration", err)
		return
	}

	b.storeMutex.Lock()
	defer b.storeMutex.Unlock()
	b.store = newdir
	b.infoLog.Printf("whawty-auth: successfully reloaded from: %s (%d parameter-sets loaded)", event.Name, len(b.store.Params))
}

func (b *WhawtyAuthBackend) initPrometheus(prom prometheus.Registerer) error {
	// TODO: add custom metrics
	return metricsCommon(prom)
}

func (b *WhawtyAuthBackend) Authenticate(username, password string) error {
	//authRequests.Inc()

	b.storeMutex.RLock()
	defer b.storeMutex.RUnlock()
	ok, _, upgradeable, _, err := b.store.Authenticate(username, password)
	if err != nil {
		authRequestsFailed.WithLabelValues().Inc()
		return err
	}
	if !ok {
		authRequestsFailed.WithLabelValues().Inc()
		return fmt.Errorf("invalid username or password")
	}
	authRequestsSuccess.WithLabelValues().Inc()
	if upgradeable && b.upgradeChan != nil {
		select {
		case b.upgradeChan <- whawtyUpgradeRequest{Username: username, OldPassword: password}:
		default: // remote upgrades are opportunistic
		}
	}
	return nil
}
