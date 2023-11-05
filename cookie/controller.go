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
	"time"
)

const (
	DefaultExpire = 24 * time.Hour
)

type SignerConfig struct {
	Name    string         `yaml:"name"`
	Ed25519 *Ed25519Config `yaml:"ed25519"`
}

type Config struct {
	Domain  string         `yaml:"domain"`
	Name    string         `yaml:"name"`
	Secure  bool           `yaml:"secure"`
	Expire  time.Duration  `yaml:"expire"`
	Signers []SignerConfig `yaml:"signers"`
}

type Signer interface {
	Sign(payload []byte) ([]byte, error)
	Verify(payload, signature []byte) error
}

type Controller struct {
	conf    *Config
	signers []Signer
}

func NewController(conf *Config) (*Controller, error) {
	if conf.Name == "" {
		conf.Name = "whawty-nginx-sso"
	}
	if conf.Expire <= 0 {
		conf.Expire = DefaultExpire
	}

	ctrl := &Controller{conf: conf}
	for _, sc := range conf.Signers {
		var s Signer
		if sc.Ed25519 != nil {
			var err error
			s, err = NewEd25519Signer(conf.Name+"_"+sc.Name, sc.Ed25519)
			if err != nil {
				return nil, fmt.Errorf("cookies: failed to initialize Ed25519 signer '%s': %v", sc.Name, err)
			}
		}
		if s == nil {
			return nil, fmt.Errorf("cookies: failed to initialize signer '%s': no valid type-specific config found", sc.Name)
		}
		ctrl.signers = append(ctrl.signers, s)
	}
	if len(ctrl.signers) < 1 {
		return nil, fmt.Errorf("cookies: at least one signer must be configured")
	}
	return ctrl, nil
}

func (c *Controller) Mint(p Payload) (name, value string, err error) {
	p.Expires = time.Now().Add(c.conf.Expire).Unix()
	v := &Value{payload: p.Encode()}
	if v.signature, err = c.signers[0].Sign(v.payload); err != nil {
		return
	}

	name = c.conf.Name
	value = v.String()
	return
}

func (c *Controller) Verify(value string) (p Payload, err error) {
	var v Value
	if err = v.FromString(value); err != nil {
		return
	}

	for _, signer := range c.signers {
		if err = signer.Verify(v.payload, v.signature); err == nil {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("cookie signature is not valid")
		return
	}

	if err = p.Decode(v.payload); err != nil {
		err = fmt.Errorf("unable to decode cookie: %v", err)
		return
	}
	if time.Unix(p.Expires, 0).Before(time.Now()) {
		err = fmt.Errorf("cookie is expired")
		return
	}
	return
}
