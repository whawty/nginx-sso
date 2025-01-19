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
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func TestSessionListEmptyJson(t *testing.T) {
	testList := SessionList{}

	out, err := testList.MarshalJSON()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(out, []byte("[]")) {
		t.Fatalf("marshalling empty SessionList to json should return '[]', got '%s'", string(out))
	}

	testListFull := SessionFullList{}
	out, err = testListFull.MarshalJSON()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(out, []byte("[]")) {
		t.Fatalf("marshalling empty SessionFullList to json should return '[]', got '%s'", string(out))
	}
}

func TestNewStore(t *testing.T) {
	conf := &Config{}
	_, err := NewStore(conf, nil, nil, nil)
	if err == nil {
		t.Fatal("initializing store from empty config should fail")
	}

	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "empty"},
	}
	_, err = NewStore(conf, nil, nil, nil)
	if err == nil {
		t.Fatal("initializing store with bogus keys config should fail")
	}

	keyFilePath := "/path/to/key.pem"
	ed25519Conf := &Ed25519Config{PrivKeyFile: &keyFilePath}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	_, err = NewStore(conf, nil, nil, nil)
	if err == nil {
		t.Fatal("initializing store with corrupt keys config entries should fail")
	}

	ed25519Conf = &Ed25519Config{PubKeyData: &testPubKeyEd25519Pem}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "test", Ed25519: ed25519Conf},
	}
	st, err := NewStore(conf, nil, nil, nil)
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
	st, err = NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if st.signer == nil {
		t.Fatal("initializing store with sign-and-verify key must have signer attribute")
	}

	conf.Backend = StoreBackendConfig{}
	_, err = NewStore(conf, nil, nil, nil)
	if err == nil {
		t.Fatal("initializing store with empty backend config should fail")
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
	st, err := NewStore(conf, nil, nil, nil)
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

func TestBackendSync(t *testing.T) {
	cookieName := "some-prefix"
	ed25519ConfVerifyOnly := &Ed25519Config{PubKeyData: &testPubKeyEd25519Pem}

	conf := &Config{Name: cookieName}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "verify-only", Ed25519: ed25519ConfVerifyOnly},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	conf.Backend.Sync = &StoreSyncConfig{BaseURL: ""}
	_, err := NewStore(conf, nil, nil, nil)
	if err == nil {
		t.Fatal("initializing store with empty sync base-url shoud fail")
	}
	conf.Backend.Sync = &StoreSyncConfig{BaseURL: "file:///not/a/http/url"}
	_, err = NewStore(conf, nil, nil, nil)
	if err == nil {
		t.Fatal("initializing store with non-http(s) sync base-url shoud fail")
	}
	conf.Backend.Sync = &StoreSyncConfig{BaseURL: "http://192.0.2.1"}
	_, err = NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestNew(t *testing.T) {
	conf := &Config{}
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "verify-only", Ed25519: &Ed25519Config{PubKeyData: &testPubKeyEd25519Pem}},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testUser := "test-user"
	testAgent := AgentInfo{Name: "test-agent", OS: "test-os"}
	_, _, err = st.New(testUser, testAgent)
	if err == nil {
		t.Fatal("calling New() on verify-only store must return an error")
	}

	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}},
	}
	st, err = NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	value, opts, err := st.New(testUser, testAgent)
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
	if s.Username != testUser {
		t.Fatalf("the username is wrong, expected: %s, got %s", testUser, s.Username)
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
	st, err := NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	_, err = st.Verify("")
	if err == nil {
		t.Fatal("verifing invalid cookie value should fail")
	}

	testSession := SessionBase{Username: "test-user", Expires: time.Now().Add(time.Hour).Unix()}
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
	_, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("signature signed by unknown signer should not verify")
	}

	testValue.payload = []byte("this-is-not-a-valid-payload")
	testValue.signature, err = st.signer.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("extracting an ivalid payload should fail")
	}

	if testValue, err = MakeValue(ulid.Make(), SessionBase{Username: "test-user", Expires: time.Now().Unix()}); err != nil {
		t.Fatal("unexpected error:", err)
	}
	testValue.signature, err = st.signer.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, err = st.Verify(testValue.String())
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

	s, err := st.Verify(testValue.String())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if s.Username != testSession.Username {
		t.Fatalf("the username is wrong, expected: %s, got %s", testSession.Username, s.Username)
	}
	if s.ID.Compare(testID) != 0 {
		t.Fatalf("the id is wrong, expected: %s, got %s", testID.String(), s.ID)
	}

	if err = st.Revoke(s); err != nil {
		t.Fatal("unexpected error:", err)
	}

	_, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("revoked session should not successfully verify")
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
	st, err := NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testUser := "test-user"
	testAgent := AgentInfo{Name: "test-agent", OS: "test-os"}
	value, _, err := st.New(testUser, testAgent)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	_, err = st.Verify(value)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	testSignerName := "secondary"
	testSigner := &Ed25519SignerVerifier{context: conf.Name + "_" + testSignerName, priv: priv, pub: pub}

	testSession := SessionBase{Username: testUser}
	testSession.Expires = time.Now().Add(time.Hour).Unix()
	testValue, err := MakeValue(ulid.Make(), testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	testValue.signature, err = testSigner.Sign(testValue.payload)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	_, err = st.Verify(testValue.String())
	if err == nil {
		t.Fatal("signature signed by unknown signer should not verify")
	}

	st.keys = append(st.keys, testSigner)
	_, err = st.Verify(testValue.String())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestListUser(t *testing.T) {
	conf := &Config{}
	conf.Name = "some-prefix"
	conf.Expire = time.Hour
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testUser := "test-user"

	list, err := st.ListUser(testUser)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 0 {
		t.Fatalf("unexpected session list length: expected 0, got %d", len(list))
	}

	testAgent1 := AgentInfo{Name: "test-agent1", OS: "test-os1"}
	value1, _, err := st.New(testUser, testAgent1)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	list, err = st.ListUser(testUser)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 1 {
		t.Fatalf("unexpected session list length: expected 1, got %d", len(list))
	}

	testAgent2 := AgentInfo{Name: "test-agent2", OS: "test-os2"}
	value2, _, err := st.New(testUser, testAgent2)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	list, err = st.ListUser(testUser)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 2 {
		t.Fatalf("unexpected session list length: expected 2, got %d", len(list))
	}

	testUser2 := "other-user"
	_, _, err = st.New(testUser2, testAgent1)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	list, err = st.ListUser(testUser)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 2 {
		t.Fatalf("unexpected session list length: expected 2, got %d", len(list))
	}

	var v1 Value
	err = v1.FromString(value1)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	s1, err := v1.Session()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	err = st.Revoke(s1)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	list, err = st.ListUser(testUser)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 1 {
		t.Fatalf("unexpected session list length: expected 1, got %d", len(list))
	}

	var v2 Value
	err = v2.FromString(value2)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	s2, err := v2.Session()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	err = st.Revoke(s2)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	list, err = st.ListUser(testUser)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 0 {
		t.Fatalf("unexpected session list length: expected 0, got %d", len(list))
	}

	list, err = st.ListUser(testUser2)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 1 {
		t.Fatalf("unexpected session list length: expected 1, got %d", len(list))
	}

	// TODO: actually compare session IDs and in session list with expected sessions
}

func TestListRevoked(t *testing.T) {
	conf := &Config{}
	conf.Name = "some-prefix"
	conf.Expire = time.Hour
	conf.Keys = []SignerVerifierConfig{
		SignerVerifierConfig{Name: "sign-and-verify", Ed25519: &Ed25519Config{PrivKeyData: &testPrivKeyEd25519Pem}},
	}
	conf.Backend = StoreBackendConfig{InMemory: &InMemoryBackendConfig{}}
	st, err := NewStore(conf, nil, nil, nil)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	testUser := "test-user"
	testAgent := AgentInfo{Name: "test-agent", OS: "test-os"}
	value, _, err := st.New(testUser, testAgent)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	signed, err := st.ListRevoked()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal([]byte("[]"), signed.Revoked) {
		t.Fatalf("unexpected revocation list: expected '[]', got '%s'", signed.Revoked)
	}
	err = st.keys[0].Verify(signed.Revoked, signed.Signature)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	var v Value
	err = v.FromString(value)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	s, err := v.Session()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	err = st.Revoke(s)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	signed, err = st.ListRevoked()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	list, err := st.verifyAndDecodeSignedRevocationList(signed)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 1 {
		t.Fatalf("unexpected revocation list length: expected 1, got %d", len(list))
	}

	value, _, err = st.New(testUser, testAgent)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	err = v.FromString(value)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	s, err = v.Session()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	err = st.RevokeID(s.Username, s.ID)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	signed, err = st.ListRevoked()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	list, err = st.verifyAndDecodeSignedRevocationList(signed)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if len(list) != 2 {
		t.Fatalf("unexpected revocation list length: expected 2, got %d", len(list))
	}

	// TODO: actually compare session IDs and in revocation list with expected sessions
}
