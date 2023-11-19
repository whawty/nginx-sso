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
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func TestNewStore(t *testing.T) {
	conf := &Config{}
	_, err := NewStore(conf, nil, nil)
	if err == nil {
		t.Fatal("initializing store from empty config should fail")
	}

	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}} // TODO: test New with empty backend config
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "empty"},
	}
	_, err = NewStore(conf, nil, nil)
	if err == nil {
		t.Fatal("initializing store with bogus keys config should fail")
	}

	keyFilePath := "/path/to/key.pem"
	ed25519Conf := &Ed25519Config{PrivKeyFile: &keyFilePath}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	_, err = NewStore(conf, nil, nil)
	if err == nil {
		t.Fatal("initializing store with corrupt keys config entries should fail")
	}

	ed25519Conf = &Ed25519Config{PubKeyData: &testPubKeyEd25519Pem}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	st, err := NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if st.conf.Name == "" {
		t.Fatal("initializing store default value for cookie name does not work")
	}
	if st.conf.Expire != DefaultExpire {
		t.Fatal("initializing store default value for cookie expiry does not work")
	}
	if st.signer != nil {
		t.Fatal("initializing store with verify-only key must not have signer attribute")
	}

	ed25519Conf = &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	st, err = NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if st.signer == nil {
		t.Fatal("initializing store with sign-and-verify key must have signer attribute")
	}
}

func TestMultipleKeys(t *testing.T) {
	cookieName := "some-prefix"
	ed25519ConfVerifyOnly := &Ed25519Config{PubKeyData: &testPubKeyEd25519Pem}
	ed25519ConfSignAndVerify := &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}

	conf := &Config{Name: cookieName}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "verify-only", Ed25519: ed25519ConfVerifyOnly},
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: ed25519ConfSignAndVerify},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if st.signer == nil {
		t.Fatal("initializing store with at least one sign-and-verify key must have signer attribute")
	}
	ed25519Signer, ok := st.signer.(*Ed25519SignerVerifier)
	if !ok {
		t.Fatalf("signer-verfier has wrong type: %T", st.signer)
	}
	expectedContext := cookieName + "_sign-and-verify"
	if ed25519Signer.context != expectedContext {
		t.Fatalf("signer has wrong context, expected: '%+v', got '%+v'", expectedContext, ed25519Signer.context)
	}
}

func TestNew(t *testing.T) {
	conf := &Config{}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "verify-only", Ed25519: &Ed25519Config{PubKeyData: &testPubKeyEd25519Pem}},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testSession := Session{Username: "test-user"}
	_, _, err = st.New(testSession)
	if err == nil {
		t.Fatal("calling New() on verify-only store must return an error")
	}

	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}},
	}
	st, err = NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	value, opts, err := st.New(testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if opts.Name != DefaultCookieName {
		t.Fatal("New() returns wrong cookie name")
	}

	var v Value
	err = v.FromString(value)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(v.payload) == 0 || len(v.signature) == 0 {
		t.Fatal("New() returned invalid value")
	}
	err = st.signer.Verify(v.payload, v.signature)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	s, err := v.Session()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if s.Username != testSession.Username {
		t.Fatalf("the username is wrong, expected: %s, got %s", testSession.Username, s.Username)
	}
	expire := time.Unix(s.Expires, 0).Sub(time.Now())
	expiresDiff := DefaultExpire - expire
	if expiresDiff < 0 || expiresDiff > 5*time.Second {
		t.Fatalf("expires: expected %v, got %v (diff: %v)", DefaultExpire, expire, expiresDiff)
	}
}

func TestVerify(t *testing.T) {
	conf := &Config{}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	_, _, err = st.Verify("")
	if err == nil {
		t.Fatal("verifing invalid cookie value should fail")
	}

	testSession := Session{Username: "test-user", Expires: time.Now().Add(time.Hour).Unix()}
	testValue, err := MakeValue(ulid.Make(), testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testSigner := &Ed25519SignerVerifier{context: DefaultCookieName + "_sign-and-verify", priv: priv, pub: pub}
	testValue.signature, err = testSigner.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, _, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("signature signed by unknown signer should not verify")
	}

	testValue.payload = []byte("this-is-not-a-valid-payload")
	testValue.signature, err = st.signer.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, _, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("extracting an ivalid payload should fail")
	}

	if testValue, err = MakeValue(ulid.Make(), Session{Username: "test-user", Expires: time.Now().Unix()}); err != nil {
		t.Fatal("unexpected error:", err)
	}
	testValue.signature, err = st.signer.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, _, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("expired cookie should not successfully verify")
	}

	testID := ulid.Make()
	if testValue, err = MakeValue(testID, testSession); err != nil {
		t.Fatal("unexpected error:", err)
	}
	testValue.signature, err = st.signer.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	id, s, err := st.Verify(testValue.String())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if s.Username != testSession.Username {
		t.Fatalf("the username is wrong, expected: %s, got %s", testSession.Username, s.Username)
	}
	if testID.String() != id {
		t.Fatalf("the id is wrong, expected: %s, got %s", testID.String(), id)
	}
}

func TestNewThenVerifyMultipleKeys(t *testing.T) {
	conf := &Config{}
	conf.Name = "some-prefix"
	conf.Expire = time.Hour
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testSession := Session{Username: "test-user"}
	value, _, err := st.New(testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	_, _, err = st.Verify(value)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	testSignerName := "secondary"
	testSigner := &Ed25519SignerVerifier{context: conf.Name + "_" + testSignerName, priv: priv, pub: pub}

	testSession.Expires = time.Now().Add(time.Hour).Unix()
	testValue, err := MakeValue(ulid.Make(), testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	testValue.signature, err = testSigner.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, _, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("signature signed by unknown signer should not verify")
	}

	st.keys = append(st.keys, testSigner)
	_, _, err = st.Verify(testValue.String())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}
