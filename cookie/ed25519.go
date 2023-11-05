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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type Ed25519Config struct {
	PrivKey     *string `yaml:"private-key"`
	PrivKeyFile *string `yaml:"private-key-file"`
	PubKey      *string `yaml:"public-key"`
	PubKeyFile  *string `yaml:"public-key-file"`
}

type Ed25519SignerVerifier struct {
	context string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
}

func loadFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

func loadEd25519PublicKey(conf *Ed25519Config) (ed25519.PublicKey, error) {
	var keyPem []byte
	if conf.PubKey != nil {
		keyPem = []byte(*conf.PubKey)
	}
	if conf.PubKeyFile != nil {
		var err error
		if keyPem, err = loadFile(*conf.PubKeyFile); err != nil {
			return nil, err
		}
	}
	if keyPem == nil {
		return nil, fmt.Errorf("no keys found")
	}

	pemBlock, _ := pem.Decode(keyPem)
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("no valid PEM encoded block found")
	}
	keyParsed, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := keyParsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a valid Ed25519 public key")
	}
	return pub, nil
}

func loadEd25519Keys(conf *Ed25519Config) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	var keyPem []byte
	if conf.PrivKey != nil {
		keyPem = []byte(*conf.PrivKey)
	}
	if conf.PrivKeyFile != nil {
		var err error
		if keyPem, err = loadFile(*conf.PrivKeyFile); err != nil {
			return nil, nil, err
		}
	}
	if keyPem == nil {
		pub, err := loadEd25519PublicKey(conf)
		return nil, pub, err
	}

	pemBlock, _ := pem.Decode(keyPem)
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("no valid PEM encoded block found")
	}
	keyParsed, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	priv, ok := keyParsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("key is not a valid Ed25519 private key")
	}

	return priv, priv.Public().(ed25519.PublicKey), nil
}

func NewEd25519SignerVerifier(context string, conf *Ed25519Config) (*Ed25519SignerVerifier, error) {
	if conf.PrivKey != nil && conf.PrivKeyFile != nil {
		return nil, fmt.Errorf("'private-key' and 'public-key-file' are mutually exclusive")
	}
	if conf.PubKey != nil && conf.PubKeyFile != nil {
		return nil, fmt.Errorf("'public-key' and 'public-key-file' are mutually exclusive")
	}

	priv, pub, err := loadEd25519Keys(conf)
	if err != nil {
		return nil, err
	}
	return &Ed25519SignerVerifier{context: context, priv: priv, pub: pub}, nil
}

func (s Ed25519SignerVerifier) Algo() string {
	return "Ed25519"
}

func (s Ed25519SignerVerifier) CanSign() bool {
	return s.priv != nil
}

func (s Ed25519SignerVerifier) Sign(payload []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, fmt.Errorf("")
	}
	return s.priv.Sign(nil, payload, &ed25519.Options{Context: s.context})
}

func (s Ed25519SignerVerifier) Verify(payload, signature []byte) error {
	return ed25519.VerifyWithOptions(s.pub, payload, signature, &ed25519.Options{Context: s.context})
}
