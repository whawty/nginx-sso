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

package cookie

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/spreadspace/tlsconfig"
)

const (
	DefaultCookieName = "whawty-nginx-sso"
	DefaultExpire     = 24 * time.Hour
)

type SignerVerifierConfig struct {
	Name    string         `yaml:"name"`
	Ed25519 *Ed25519Config `yaml:"ed25519"`
}

type StoreSyncConfig struct {
	Interval  time.Duration        `yaml:"interval"`
	BaseURL   string               `yaml:"base-url"`
	TLSConfig *tlsconfig.TLSConfig `yaml:"tls"`
	Token     string               `yaml:"token"`
}

type StoreBackendConfig struct {
	GCInterval time.Duration          `yaml:"gc-interval"`
	Sync       *StoreSyncConfig       `yaml:"sync"`
	InMemory   *InMemoryBackendConfig `yaml:"in-memory"`
}

type Config struct {
	Name    string                 `yaml:"name"`
	Domain  string                 `yaml:"domain"`
	Secure  bool                   `yaml:"secure"`
	Expire  time.Duration          `yaml:"expire"`
	Keys    []SignerVerifierConfig `yaml:"keys"`
	Backend StoreBackendConfig     `yaml:"backend"`
}

type SignerVerifier interface {
	Algo() string
	CanSign() bool
	Sign(payload []byte) ([]byte, error)
	Verify(payload, signature []byte) error
}

type StoredSession struct {
	ID      ulid.ULID `json:"id"`
	Session Session   `josn:"session"`
}

type StoredSessionList []StoredSession

func (l StoredSessionList) MarshalJSON() ([]byte, error) {
	if len(l) == 0 {
		return []byte("[]"), nil
	}
	var tmp []StoredSession = l
	return json.Marshal(tmp)
}

type SignedRevocationList struct {
	Revoked   json.RawMessage `json:"revoked"`
	Signature []byte          `json:"signature"`
}

type StoreBackend interface {
	Save(id ulid.ULID, session Session) error
	ListUser(username string) (StoredSessionList, error)
	Revoke(id ulid.ULID, session Session) error
	IsRevoked(id ulid.ULID) (bool, error)
	ListRevoked() (StoredSessionList, error)
	LoadRevocations(StoredSessionList) (uint, error)
	CollectGarbage() (uint, error)
}

type Options struct {
	Name   string
	MaxAge int
	Domain string
	Secure bool
}

func (opts *Options) fromConfig(conf *Config) {
	opts.Name = conf.Name
	opts.MaxAge = int(conf.Expire.Seconds())
	opts.Domain = conf.Domain
	opts.Secure = conf.Secure
}

type Store struct {
	conf    *Config
	keys    []SignerVerifier
	signer  SignerVerifier
	backend StoreBackend
	infoLog *log.Logger
	dbgLog  *log.Logger
}

func NewStore(conf *Config, infoLog, dbgLog *log.Logger) (*Store, error) {
	if infoLog == nil {
		infoLog = log.New(io.Discard, "", 0)
	}
	if dbgLog == nil {
		dbgLog = log.New(io.Discard, "", 0)
	}

	if conf.Name == "" {
		conf.Name = DefaultCookieName
	}
	if conf.Expire <= 0 {
		conf.Expire = DefaultExpire
	}

	st := &Store{conf: conf, infoLog: infoLog, dbgLog: dbgLog}
	if err := st.initKeys(conf); err != nil {
		st.infoLog.Printf("cookie-store: failed to initialize keys: %v", err)
		return nil, err
	}
	if err := st.initBackend(conf); err != nil {
		st.infoLog.Printf("cookie-store: failed to initialize backend: %v", err)
		return nil, err
	}
	st.infoLog.Printf("cookie-store: successfully initialized (%d keys loaded)", len(st.keys))
	if st.signer == nil {
		st.infoLog.Printf("cookie-store: no signing key has been loaded - this instance can only verify cookies")
	}
	return st, nil
}

func (st *Store) initKeys(conf *Config) (err error) {
	for _, key := range conf.Keys {
		var s SignerVerifier
		if key.Ed25519 != nil {
			s, err = NewEd25519SignerVerifier(conf.Name+"_"+key.Name, key.Ed25519)
			if err != nil {
				return fmt.Errorf("failed to load Ed25519 key '%s': %v", key.Name, err)
			}
		}
		if s == nil {
			return fmt.Errorf("failed to load key '%s': no valid type-specific config found", key.Name)
		}

		st.keys = append(st.keys, s)
		mode := "(verify-only)"
		if s.CanSign() && st.signer == nil {
			st.signer = s
			mode = "(*sign* and verify)"
		}
		st.dbgLog.Printf("cookie-store: loaded %s key '%s' %s", s.Algo(), key.Name, mode)
	}
	if len(st.keys) < 1 {
		return fmt.Errorf("at least one key must be configured")
	}
	return
}

func (st *Store) runGC(interval time.Duration) {
	t := time.NewTicker(interval)
	st.dbgLog.Printf("cookie-store: running GC every %v", interval)
	for {
		if _, ok := <-t.C; !ok {
			return
		}
		cnt, err := st.backend.CollectGarbage()
		if err != nil {
			st.infoLog.Printf("cookie-store: failed to collect garbage: %v", err)
		}
		if cnt > 0 {
			st.dbgLog.Printf("cookie-store: GC removed %d expired sessions", cnt)
		}
	}
}

func (st *Store) syncRevocations(client *http.Client, syncBaseURL *url.URL, token string) {
	req, _ := http.NewRequest("GET", syncBaseURL.JoinPath("revocations").String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		st.infoLog.Printf("sync-store: error sending sync request: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		st.infoLog.Printf("sync-store: error sending sync request: got HTTP status code %d", resp.StatusCode)
		return
	}

	var signed SignedRevocationList
	err = json.NewDecoder(resp.Body).Decode(&signed)
	resp.Body.Close()
	if err != nil {
		st.infoLog.Printf("sync-store: error parsing sync response: %v", err)
		return
	}

	for _, key := range st.keys {
		if err = key.Verify(signed.Revoked, signed.Signature); err == nil {
			break
		}
	}
	if err != nil {
		st.infoLog.Printf("sync-store: revocation list signature is invalid")
		return
	}

	var list StoredSessionList
	if err = json.Unmarshal(signed.Revoked, &list); err != nil {
		st.infoLog.Printf("sync-store: error parsing sync response: %v", err)
		return
	}

	var cnt uint
	if cnt, err = st.backend.LoadRevocations(list); err != nil {
		st.infoLog.Printf("sync-state: error loading revocations: %v", err)
		return
	}
	if cnt > 0 {
		st.dbgLog.Printf("sync-state: successfully synced %d revocations", cnt)
	}
}

func (st *Store) runSync(interval time.Duration, syncBaseURL *url.URL, tlsConfig *tls.Config, token string) {
	client := &http.Client{}
	switch syncBaseURL.Scheme {
	case "http":
		st.infoLog.Printf("sync-store: using insecure url for sync: %s", syncBaseURL.String())
	case "https":
		if tlsConfig != nil {
			client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
			if tlsConfig.InsecureSkipVerify {
				st.infoLog.Printf("sync-store: certificate checks for sync are disabled!")
			}
		}
	}

	t := time.NewTicker(interval)
	st.dbgLog.Printf("cookie-store: running sync every %v", interval)
	for {
		if _, ok := <-t.C; !ok {
			return
		}
		st.syncRevocations(client, syncBaseURL, token)
	}
}

func (st *Store) initBackend(conf *Config) (err error) {
	if conf.Backend.GCInterval <= time.Second {
		st.infoLog.Printf("cookie-store: overriding invalid/unset GC interval to 5 minutes")
		conf.Backend.GCInterval = 5 * time.Minute
	}
	var syncBaseURL *url.URL
	var syncTLSConfig *tls.Config
	if conf.Backend.Sync != nil {
		if syncBaseURL, err = url.Parse(conf.Backend.Sync.BaseURL); err != nil {
			return
		}
		if syncBaseURL.Scheme != "http" && syncBaseURL.Scheme != "https" {
			err = fmt.Errorf("sync base-url '%s' is invalid", conf.Backend.Sync.BaseURL)
			return
		}
		if conf.Backend.Sync.Interval <= time.Second {
			st.infoLog.Printf("cookie-store: overriding invalid/unset GC interval to 10 seconds")
			conf.Backend.Sync.Interval = 10 * time.Second
		}
		if conf.Backend.Sync.TLSConfig != nil {
			if syncTLSConfig, err = conf.Backend.Sync.TLSConfig.ToGoTLSConfig(); err != nil {
				return
			}
		}
	}

	if conf.Backend.InMemory != nil {
		st.backend, err = NewInMemoryBackend(conf.Backend.InMemory)
		if err != nil {
			return err
		}
	}
	// TODO: add other backend types
	if st.backend == nil {
		err = fmt.Errorf("no valid backend configuration found")
		return
	}

	go st.runGC(conf.Backend.GCInterval)
	if conf.Backend.Sync != nil {
		go st.runSync(conf.Backend.Sync.Interval, syncBaseURL, syncTLSConfig, conf.Backend.Sync.Token)
	}
	return
}

func (st *Store) Options() (opts Options) {
	opts.fromConfig(st.conf)
	return
}

func (st *Store) New(s Session) (value string, opts Options, err error) {
	if st.signer == nil {
		err = fmt.Errorf("no signing key loaded")
		return
	}

	s.SetExpiry(st.conf.Expire)
	id := ulid.Make()
	var v *Value
	if v, err = MakeValue(id, s); err != nil {
		return
	}
	if v.signature, err = st.signer.Sign(v.payload); err != nil {
		return
	}

	if err = st.backend.Save(id, s); err != nil {
		return
	}
	st.dbgLog.Printf("successfully generated new session('%v'): %+v", id, s)

	opts.fromConfig(st.conf)
	value = v.String()
	return
}

func (st *Store) Verify(value string) (id string, s Session, err error) {
	var v Value
	if err = v.FromString(value); err != nil {
		return
	}

	for _, key := range st.keys {
		if err = key.Verify(v.payload, v.signature); err == nil {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("cookie signature is not valid")
		return
	}

	var _id ulid.ULID
	if _id, err = v.ID(); err != nil {
		err = fmt.Errorf("unable to decode cookie: %v", err)
		return
	}
	id = _id.String()

	var revoked bool
	if revoked, err = st.backend.IsRevoked(_id); err != nil {
		err = fmt.Errorf("failed to check for cookie revocation: %v", err)
		return
	}
	if revoked {
		err = fmt.Errorf("cookie is revoked")
		return
	}

	if s, err = v.Session(); err != nil {
		err = fmt.Errorf("unable to decode cookie: %v", err)
		return
	}
	if s.IsExpired() {
		err = fmt.Errorf("cookie is expired")
		return
	}

	st.dbgLog.Printf("successfully verified session('%v'): %+v", id, s)
	return
}

func (st *Store) ListUser(username string) (StoredSessionList, error) {
	return st.backend.ListUser(username)
}

func (st *Store) Revoke(id string, session Session) error {
	toRevoke, err := ulid.ParseStrict(id)
	if err != nil {
		return err
	}
	if err = st.backend.Revoke(toRevoke, session); err != nil {
		return err
	}
	st.dbgLog.Printf("successfully revoked session('%v')", id)
	return nil
}

func (st *Store) ListRevoked() (result SignedRevocationList, err error) {
	var revoked StoredSessionList
	if revoked, err = st.backend.ListRevoked(); err != nil {
		return
	}

	if result.Revoked, err = json.Marshal(revoked); err != nil {
		return
	}
	if st.signer != nil {
		if result.Signature, err = st.signer.Sign(result.Revoked); err != nil {
			return
		}
	}
	return
}
