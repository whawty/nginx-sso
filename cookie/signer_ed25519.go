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

// TODO: split up signer and verifier!!!

type Ed25519Config struct {
	Key     *string `yaml:"key"`
	KeyFile *string `yaml:"key_file"`
}

type Ed25519Signer struct {
	context string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
}

func NewEd25519Signer(context string, conf *Ed25519Config) (*Ed25519Signer, error) {
	if conf.Key != nil && conf.KeyFile != nil {
		return nil, fmt.Errorf("'key' and 'key_file' are mutually exclusive")
	}

	var keyPem []byte
	if conf.Key != nil {
		keyPem = []byte(*conf.Key)
	}
	if conf.KeyFile != nil {
		kf, err := os.Open(*conf.KeyFile)
		if err != nil {
			return nil, err
		}
		defer kf.Close()

		if keyPem, err = io.ReadAll(kf); err != nil {
			return nil, err
		}
	}
	if keyPem == nil {
		return nil, fmt.Errorf("please set 'key' or 'key_file'")
	}

	pemBlock, _ := pem.Decode(keyPem)
	if pemBlock == nil {
		return nil, fmt.Errorf("no valid PEM encoded block found")
	}
	keyParsed, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := keyParsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not a valid Ed25519 key")
	}
	pub := priv.Public().(ed25519.PublicKey)

	return &Ed25519Signer{context: context, priv: priv, pub: pub}, nil
}

func (s Ed25519Signer) Sign(payload []byte) ([]byte, error) {
	return s.priv.Sign(nil, payload, &ed25519.Options{Context: s.context})
}

func (s Ed25519Signer) Verify(payload, signature []byte) error {
	return ed25519.VerifyWithOptions(s.pub, payload, signature, &ed25519.Options{Context: s.context})
}
