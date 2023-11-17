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
	"fmt"
	"io"
	"log"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	DefaultCookieName = "whawty-nginx-sso"
	DefaultExpire     = 24 * time.Hour
)

type SignerVerifierConfig struct {
	Name    string         `yaml:"name"`
	Ed25519 *Ed25519Config `yaml:"ed25519"`
}

type Config struct {
	Name   string                 `yaml:"name"`
	Domain string                 `yaml:"domain"`
	Secure bool                   `yaml:"secure"`
	Expire time.Duration          `yaml:"expire"`
	Keys   []SignerVerifierConfig `yaml:"keys"`
}

type SignerVerifier interface {
	Algo() string
	CanSign() bool
	Sign(payload []byte) ([]byte, error)
	Verify(payload, signature []byte) error
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

type Controller struct {
	conf    *Config
	keys    []SignerVerifier
	signer  SignerVerifier
	infoLog *log.Logger
	dbgLog  *log.Logger
}

func NewController(conf *Config, infoLog, dbgLog *log.Logger) (*Controller, error) {
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

	ctrl := &Controller{conf: conf, infoLog: infoLog, dbgLog: dbgLog}
	if err := ctrl.initKeys(conf); err != nil {
		return nil, err
	}
	ctrl.infoLog.Printf("cookie-controller: successfully initialized (%d keys loaded)", len(ctrl.keys))
	if ctrl.signer == nil {
		ctrl.infoLog.Printf("cookie-controller: no signing key has been loaded - this instance can only verify cookies")
	}
	return ctrl, nil
}

func (c *Controller) initKeys(conf *Config) (err error) {
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

		c.keys = append(c.keys, s)
		mode := "(verify-only)"
		if s.CanSign() && c.signer == nil {
			c.signer = s
			mode = "(*sign* and verify)"
		}
		c.dbgLog.Printf("cookie-controller: loaded %s key '%s' %s", s.Algo(), key.Name, mode)
	}
	if len(c.keys) < 1 {
		return fmt.Errorf("at least one key must be configured")
	}
	return
}

func (c *Controller) Options() (opts Options) {
	opts.fromConfig(c.conf)
	return
}

func (c *Controller) New(s Session) (value string, opts Options, err error) {
	if c.signer == nil {
		err = fmt.Errorf("no signing key loaded")
		return
	}

	s.Expires = time.Now().Add(c.conf.Expire).Unix()
	v := &Value{}
	var id ulid.ULID
	if id, err = v.generatePayload(s); err != nil {
		return
	}
	if v.signature, err = c.signer.Sign(v.payload); err != nil {
		return
	}

	// TODO: store session
	c.dbgLog.Printf("successfully generated new session('%v'): %+v", id, s)

	opts.fromConfig(c.conf)
	value = v.String()
	return
}

func (c *Controller) Verify(value string) (s Session, err error) {
	var v Value
	if err = v.FromString(value); err != nil {
		return
	}

	for _, key := range c.keys {
		if err = key.Verify(v.payload, v.signature); err == nil {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("cookie signature is not valid")
		return
	}

	var id ulid.ULID
	if id, err = v.ID(); err != nil {
		err = fmt.Errorf("unable to decode cookie: %v", err)
		return
	}

	// TODO: check if id is revoked

	if s, err = v.Session(); err != nil {
		err = fmt.Errorf("unable to decode cookie: %v", err)
		return
	}
	if time.Unix(s.Expires, 0).Before(time.Now()) {
		err = fmt.Errorf("cookie is expired")
		return
	}

	c.dbgLog.Printf("successfully verified session('%v'): %+v", id, s)
	return
}
