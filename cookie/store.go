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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spreadspace/tlsconfig"
)

const (
	DefaultCookieName = "whawty-nginx-sso"
	DefaultExpire     = 24 * time.Hour
	metricsSubsystem  = "cookie"
)

var (
	cookiesCreated         = prometheus.NewCounter(prometheus.CounterOpts{Subsystem: metricsSubsystem, Name: "created_total"})
	cookiesVerified        = prometheus.NewCounterVec(prometheus.CounterOpts{Subsystem: metricsSubsystem, Name: "verified_total"}, []string{"result"})
	cookiesVerifiedSuccess = cookiesVerified.MustCurryWith(prometheus.Labels{"result": "success"})
	cookiesVerifiedFailed  = cookiesVerified.MustCurryWith(prometheus.Labels{"result": "failed"})

	cookieSyncRequests        = prometheus.NewCounterVec(prometheus.CounterOpts{Subsystem: metricsSubsystem, Name: "sync_requests_total"}, []string{"result"})
	cookieSyncRequestsSuccess = cookieSyncRequests.MustCurryWith(prometheus.Labels{"result": "success"})
	cookieSyncRequestsFailed  = cookieSyncRequests.MustCurryWith(prometheus.Labels{"result": "failed"})
	cookieSyncRequestDuration = prometheus.NewSummary(prometheus.SummaryOpts{
		Subsystem: metricsSubsystem, Name: "sync_request_duration_seconds",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}})
)

type SignerVerifierConfig struct {
	Name    string         `yaml:"name"`
	Ed25519 *Ed25519Config `yaml:"ed25519"`
}

type StoreSyncConfig struct {
	Interval  time.Duration        `yaml:"interval"`
	BaseURL   string               `yaml:"base-url"`
	HTTPHost  string               `yaml:"http-host"`
	TLSConfig *tlsconfig.TLSConfig `yaml:"tls"`
	Token     string               `yaml:"token"`
}

type StoreBackendConfig struct {
	GCInterval time.Duration          `yaml:"gc-interval"`
	Sync       *StoreSyncConfig       `yaml:"sync"`
	InMemory   *InMemoryBackendConfig `yaml:"in-memory"`
	Bolt       *BoltBackendConfig     `yaml:"bolt"`
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

type SessionList []Session

func (l SessionList) MarshalJSON() ([]byte, error) {
	if len(l) == 0 {
		return []byte("[]"), nil
	}
	var tmp []Session = l
	return json.Marshal(tmp)
}

type AgentInfo struct {
	Name       string `json:"name"`
	OS         string `json:"os"`
	DeviceType string `json:"device-type"`
}

const (
	DeviceTypeMobile  = "Mobile"
	DeviceTypeTablet  = "Tablet"
	DeviceTypeDesktop = "Desktop"
	DeviceTypeBot     = "Bot"
)

type SessionFull struct {
	Session
	Agent AgentInfo `json:"agent"`
}

func (s SessionFull) CreatedAt() time.Time {
	return s.Session.CreatedAt()
}

func (s SessionFull) ExpiresAt() time.Time {
	return s.Session.ExpiresAt()
}

type SessionFullList []SessionFull

func (l SessionFullList) MarshalJSON() ([]byte, error) {
	if len(l) == 0 {
		return []byte("[]"), nil
	}
	var tmp []SessionFull = l
	return json.Marshal(tmp)
}

type SignedRevocationList struct {
	Revoked   json.RawMessage `json:"revoked"`
	Signature []byte          `json:"signature"`
}

type StoreBackend interface {
	Name() string
	Save(session SessionFull) error
	ListUser(username string) (SessionFullList, error)
	Revoke(session Session) error
	RevokeID(username string, id ulid.ULID) error
	IsRevoked(session Session) (bool, error)
	ListRevoked() (SessionList, error)
	LoadRevocations(SessionList) (uint, error)
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

func NewStore(conf *Config, prom prometheus.Registerer, infoLog, dbgLog *log.Logger) (*Store, error) {
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
	if err := st.initBackend(conf, prom); err != nil {
		st.infoLog.Printf("cookie-store: failed to initialize backend: %v", err)
		return nil, err
	}
	if prom != nil {
		if err := st.initPrometheus(prom); err != nil {
			st.infoLog.Printf("cookie-store: failed to initialize prometheus metrics: %v", err)
			return nil, err
		}
	}
	st.infoLog.Printf("cookie-store: successfully initialized (%d keys loaded) using backend: %s", len(st.keys), st.backend.Name())
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
			st.infoLog.Printf("cookie-store: stopping GC because ticker-channel is closed")
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

func (st *Store) verifyAndDecodeSignedRevocationList(signed SignedRevocationList) (list SessionList, err error) {
	for _, key := range st.keys {
		if err = key.Verify(signed.Revoked, signed.Signature); err == nil {
			break
		}
	}
	if err != nil {
		st.infoLog.Printf("sync-store: revocation list signature is invalid")
		return
	}

	if err = json.Unmarshal(signed.Revoked, &list); err != nil {
		st.infoLog.Printf("sync-store: error parsing sync response: %v", err)
		return
	}
	return
}

func (st *Store) syncRevocations(client *http.Client, baseURL *url.URL, host, token string) bool {
	req, _ := http.NewRequest("GET", baseURL.JoinPath("revocations").String(), nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		st.infoLog.Printf("sync-store: error sending sync request: %v", err)
		return false
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		st.infoLog.Printf("sync-store: error sending sync request: got HTTP status code %d", resp.StatusCode)
		return false
	}

	var signed SignedRevocationList
	err = json.NewDecoder(resp.Body).Decode(&signed)
	if err != nil {
		st.infoLog.Printf("sync-store: error parsing sync response: %v", err)
		return false
	}

	var list SessionList
	list, err = st.verifyAndDecodeSignedRevocationList(signed)
	if err != nil {
		return false
	}

	var cnt uint
	if cnt, err = st.backend.LoadRevocations(list); err != nil {
		st.infoLog.Printf("sync-state: error loading revocations: %v", err)
		return false
	}
	if cnt > 0 {
		st.dbgLog.Printf("sync-state: successfully synced %d revocations", cnt)
	}
	return true
}

func (st *Store) runSync(interval time.Duration, baseURL *url.URL, host string, tlsConfig *tls.Config, token string) {
	client := &http.Client{}
	switch baseURL.Scheme {
	case "http":
		st.infoLog.Printf("sync-store: using insecure url for sync: %s", baseURL.String())
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
			st.infoLog.Printf("cookie-store: stopping sync because ticker-channel is closed")
			return
		}
		now := time.Now()
		ok := st.syncRevocations(client, baseURL, host, token)
		cookieSyncRequestDuration.Observe(time.Since(now).Seconds())
		if ok {
			cookieSyncRequestsSuccess.WithLabelValues().Inc()
		} else {
			cookieSyncRequestsFailed.WithLabelValues().Inc()
		}
	}
}

func (st *Store) initBackend(conf *Config, prom prometheus.Registerer) (err error) {
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
			st.infoLog.Printf("cookie-store: overriding invalid/unset sync interval to 10 seconds")
			conf.Backend.Sync.Interval = 10 * time.Second
		}
		if conf.Backend.Sync.TLSConfig != nil {
			if syncTLSConfig, err = conf.Backend.Sync.TLSConfig.ToGoTLSConfig(); err != nil {
				return
			}
		}
	}

	if conf.Backend.InMemory != nil {
		st.backend, err = NewInMemoryBackend(conf.Backend.InMemory, prom)
		if err != nil {
			return err
		}
	}
	if conf.Backend.Bolt != nil {
		st.backend, err = NewBoltBackend(conf.Backend.Bolt, prom)
		if err != nil {
			return err
		}
	}
	if st.backend == nil {
		err = fmt.Errorf("no valid backend configuration found")
		return
	}

	go st.runGC(conf.Backend.GCInterval)
	if conf.Backend.Sync != nil {
		go st.runSync(conf.Backend.Sync.Interval, syncBaseURL, conf.Backend.Sync.HTTPHost, syncTLSConfig, conf.Backend.Sync.Token)
	}
	return
}

func (st *Store) initPrometheus(prom prometheus.Registerer) (err error) {
	if err = prom.Register(cookiesCreated); err != nil {
		return
	}
	if err = prom.Register(cookiesVerified); err != nil {
		return
	}
	cookiesVerifiedSuccess.WithLabelValues()
	cookiesVerifiedFailed.WithLabelValues()

	if err = prom.Register(cookieSyncRequests); err != nil {
		return
	}
	cookieSyncRequestsSuccess.WithLabelValues()
	cookieSyncRequestsFailed.WithLabelValues()
	if err = prom.Register(cookieSyncRequestDuration); err != nil {
		return
	}
	return nil
}

func (st *Store) Options() (opts Options) {
	opts.fromConfig(st.conf)
	return
}

func (st *Store) New(username string, ai AgentInfo) (value string, opts Options, err error) {
	if st.signer == nil {
		err = fmt.Errorf("no signing key loaded")
		return
	}

	s := SessionBase{Username: username}
	s.SetExpiry(st.conf.Expire)
	id := ulid.Make()
	var v *Value
	if v, err = MakeValue(id, s); err != nil {
		return
	}
	if v.signature, err = st.signer.Sign(v.payload); err != nil {
		return
	}

	if err = st.backend.Save(SessionFull{Session: Session{ID: id, SessionBase: s}, Agent: ai}); err != nil {
		return
	}
	st.dbgLog.Printf("successfully generated new session('%v'): %+v", id, s)

	cookiesCreated.Inc()
	opts.fromConfig(st.conf)
	value = v.String()
	return
}

func (st *Store) verify(value string) (s Session, err error) {
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

	if s, err = v.Session(); err != nil {
		err = fmt.Errorf("unable to decode cookie: %v", err)
		return
	}
	if s.IsExpired() {
		err = fmt.Errorf("cookie is expired")
		return
	}

	var revoked bool
	if revoked, err = st.backend.IsRevoked(s); err != nil {
		err = fmt.Errorf("failed to check for cookie revocation: %v", err)
		return
	}
	if revoked {
		err = fmt.Errorf("cookie is revoked")
		return
	}

	st.dbgLog.Printf("successfully verified session('%v'): %+v", s.ID, s.SessionBase)
	return
}

func (st *Store) Verify(value string) (s Session, err error) {
	s, err = st.verify(value)
	if err != nil {
		cookiesVerifiedFailed.WithLabelValues().Inc()
	} else {
		cookiesVerifiedSuccess.WithLabelValues().Inc()
	}
	return
}

func (st *Store) ListUser(username string) (SessionFullList, error) {
	return st.backend.ListUser(username)
}

func (st *Store) Revoke(session Session) error {
	if err := st.backend.Revoke(session); err != nil {
		return err
	}
	st.dbgLog.Printf("successfully revoked session('%v')", session.ID)
	return nil
}

func (st *Store) RevokeID(username string, id ulid.ULID) error {
	if err := st.backend.RevokeID(username, id); err != nil {
		return err
	}
	st.dbgLog.Printf("successfully revoked session('%v')", id)
	return nil
}

func (st *Store) ListRevoked() (result SignedRevocationList, err error) {
	var revoked SessionList
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
