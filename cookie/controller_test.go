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
	"testing"
)

func TestNewController(t *testing.T) {
	conf := &Config{}
	_, err := NewController(conf, nil, nil)
	if err == nil {
		t.Fatal("initializing controller from empty config should fail")
	}

	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "empty"},
	}
	_, err = NewController(conf, nil, nil)
	if err == nil {
		t.Fatal("initializing controller with bogus keys config should fail")
	}

	keyFilePath := "/path/to/key.pem"
	ed25519Conf := &Ed25519Config{PrivKeyFile: &keyFilePath}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	_, err = NewController(conf, nil, nil)
	if err == nil {
		t.Fatal("initializing controller with corrupt keys config entries should fail")
	}

	ed25519Conf = &Ed25519Config{PubKey: &testPubKeyEd25519Pem}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	ctrl, err := NewController(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if ctrl.conf.Name == "" {
		t.Fatal("initializing controller default value for cookie name does not work")
	}
	if ctrl.conf.Expire != DefaultExpire {
		t.Fatal("initializing controller default value for cookie expiry does not work")
	}
	if ctrl.signer != nil {
		t.Fatal("initializing controller with verify-only key must not have signer attribute")
	}

	ed25519Conf = &Ed25519Config{PrivKey: &testPrivKeyEd25519Pem}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	ctrl, err = NewController(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if ctrl.signer == nil {
		t.Fatal("initializing controller with sign-and-verify key must have signer attribute")
	}
}

func TestMultipleKeys(t *testing.T) {
	cookieName := "some-prefix"
	ed25519ConfVerifyOnly := &Ed25519Config{PubKey: &testPubKeyEd25519Pem}
	ed25519ConfSignAndVerify := &Ed25519Config{PrivKey: &testPrivKeyEd25519Pem}

	conf := &Config{Name: cookieName}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "verify-only", Ed25519: ed25519ConfVerifyOnly},
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: ed25519ConfSignAndVerify},
	}
	ctrl, err := NewController(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if ctrl.signer == nil {
		t.Fatal("initializing controller with at least one sign-and-verify key must have signer attribute")
	}
	ed25519Signer, ok := ctrl.signer.(*Ed25519SignerVerifier)
	if !ok {
		t.Fatalf("signer-verfier has wrong type: %T", ctrl.signer)
	}
	expectedContext := cookieName + "_sign-and-verify"
	if ed25519Signer.context != expectedContext {
		t.Fatalf("signer has wrong context, expected: '%+v', got '%+v'", expectedContext, ed25519Signer.context)
	}
}

// TODO: add test functions for Mint() and Verify()
