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
)

var (
	testNoPemBlocks = "there are no PEM Blocks here"

	testInvalidPubB64Pem = `
-----BEGIN PUBLIC KEY-----
this is not a public key
-----END PUBLIC KEY-----
`
	testInvalidPubKeyPem = `
-----BEGIN PUBLIC KEY-----
aGVsbG8sIHdvcmxkCg==
-----END PUBLIC KEY-----
`
	testInvalidPrivB64Pem = `
-----BEGIN PRIVATE KEY-----
this is not a public key
-----END PRIVATE KEY-----
`
	testInvalidPrivKeyPem = `
-----BEGIN PRIVATE KEY-----
aGVsbG8sIHdvcmxkCg==
-----END PRIVATE KEY-----
`

	testPubKeyEcDSA224Pem = `
-----BEGIN PUBLIC KEY-----
ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEg3Ya40PM3mvIvQnQJ+H6PoHmN6AeV0sC
AXWm/CtF9WeOnGKl1ZY++06BNll/D+44uA80qLSAuvQ=
-----END PUBLIC KEY-----
`
	testPrivKeyEcDSA224Pem = `
-----BEGIN PRIVATE KEY-----
MHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBx/TrQWr5HtQ16lAUpkO9K6
o+5oM2XVuzzx1PpZoTwDOgAEg3Ya40PM3mvIvQnQJ+H6PoHmN6AeV0sCAXWm/CtF
9WeOnGKl1ZY++06BNll/D+44uA80qLSAuvQ=
-----END PRIVATE KEY-----
`

	testPubKeyEd25519Pem = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEASk+F/AYbQpGfUDTiEcIDRON5D7BJcwgjfS60fSiw0rM=
-----END PUBLIC KEY-----
`
	testPubKeyEd25519Bytes = ed25519.PublicKey{
		0x4a, 0x4f, 0x85, 0xfc, 0x6, 0x1b, 0x42, 0x91, 0x9f, 0x50, 0x34, 0xe2, 0x11, 0xc2, 0x3, 0x44,
		0xe3, 0x79, 0xf, 0xb0, 0x49, 0x73, 0x8, 0x23, 0x7d, 0x2e, 0xb4, 0x7d, 0x28, 0xb0, 0xd2, 0xb3}

	testPrivKeyEd25519Pem = `
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG2TybpzwnGPXRU7ekqjCSR3OfIHfv2l4SSvzY0Zw01M
-----END PRIVATE KEY-----
`
	testPrivKeyEd25519Bytes = ed25519.PrivateKey{
		0x6d, 0x93, 0xc9, 0xba, 0x73, 0xc2, 0x71, 0x8f, 0x5d, 0x15, 0x3b, 0x7a, 0x4a, 0xa3, 0x9, 0x24,
		0x77, 0x39, 0xf2, 0x7, 0x7e, 0xfd, 0xa5, 0xe1, 0x24, 0xaf, 0xcd, 0x8d, 0x19, 0xc3, 0x4d, 0x4c,
		0x4a, 0x4f, 0x85, 0xfc, 0x6, 0x1b, 0x42, 0x91, 0x9f, 0x50, 0x34, 0xe2, 0x11, 0xc2, 0x3, 0x44,
		0xe3, 0x79, 0xf, 0xb0, 0x49, 0x73, 0x8, 0x23, 0x7d, 0x2e, 0xb4, 0x7d, 0x28, 0xb0, 0xd2, 0xb3}
)

func TestLoadEd25519PublicKey(t *testing.T) {
	conf := &Ed25519Config{}
	pub, err := loadEd25519PublicKey(conf)
	if err == nil {
		t.Fatal("loading public key from empty config should fail")
	}

	invalidVectors := []string{testNoPemBlocks, testInvalidPubB64Pem, testInvalidPubKeyPem, testPubKeyEcDSA224Pem, testPrivKeyEd25519Pem}
	for _, vector := range invalidVectors {
		conf.PubKey = &vector
		_, err = loadEd25519PublicKey(conf)
		if err == nil {
			t.Fatalf("loading public key from invalid key config should fail: %s", vector)
		}
	}

	conf.PubKey = &testPubKeyEd25519Pem
	pub, err = loadEd25519PublicKey(conf)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if bytes.Compare(pub, testPubKeyEd25519Bytes) != 0 {
		t.Fatalf("loading public key failed, expected: '%#v', got '%#v'", testPubKeyEd25519Bytes, pub)
	}
}

func TestLoadEd25519PublicKeyFile(t *testing.T) {
	conf := &Ed25519Config{}
	keyFilePath := "/nonexistent/key.pem"
	conf.PubKeyFile = &keyFilePath
	_, err := loadEd25519PublicKey(conf)
	if err == nil {
		t.Fatal("loading public key from not existing file should fail")
	}
	// TODO: add test with correct file
}

func TestLoadEd25519Keys(t *testing.T) {
	conf := &Ed25519Config{}
	priv, pub, err := loadEd25519Keys(conf)
	if err == nil {
		t.Fatal("loading private/public key from empty config should fail")
	}

	invalidVectors := []string{testNoPemBlocks, testInvalidPrivB64Pem, testInvalidPrivKeyPem, testPrivKeyEcDSA224Pem, testPubKeyEd25519Pem}
	for _, vector := range invalidVectors {
		conf.PrivKey = &vector
		_, _, err = loadEd25519Keys(conf)
		if err == nil {
			t.Fatalf("loading private key from invalid key config should fail: %s", vector)
		}
	}

	conf.PrivKey = &testPrivKeyEd25519Pem
	priv, pub, err = loadEd25519Keys(conf)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if bytes.Compare(priv, testPrivKeyEd25519Bytes) != 0 {
		t.Fatalf("loading private key failed, expected: '%#v', got '%#v'", testPrivKeyEd25519Bytes, priv)
	}
	if bytes.Compare(pub, testPubKeyEd25519Bytes) != 0 {
		t.Fatalf("loading public key failed, expected: '%#v', got '%#v'", testPubKeyEd25519Bytes, pub)
	}
}

func TestLoadEd25519KeysFile(t *testing.T) {
	conf := &Ed25519Config{}
	keyFilePath := "/nonexistent/key.pem"
	conf.PrivKeyFile = &keyFilePath
	_, _, err := loadEd25519Keys(conf)
	if err == nil {
		t.Fatal("loading private key from not existing file should fail")
	}
	// TODO: add test with correct file
}

func TestNewEd25519SignerVerifier(t *testing.T) {
	conf := &Ed25519Config{}
	_, err := NewEd25519SignerVerifier("foo", conf)
	if err == nil {
		t.Fatal("initializing Ed25519 Signer/Verifier from empty config should fail")
	}

	keyFilePath := "/path/to/key.pem"

	conf.PrivKey = &testPrivKeyEd25519Pem
	conf.PrivKeyFile = &keyFilePath
	_, err = NewEd25519SignerVerifier("foo", conf)
	if err == nil {
		t.Fatal("initializing Ed25519 Signer/Verifier with both priv-key and priv-key-file should fail")
	}

	conf.PrivKey = nil
	conf.PrivKeyFile = nil
	conf.PubKey = &testPubKeyEd25519Pem
	conf.PubKeyFile = &keyFilePath

	_, err = NewEd25519SignerVerifier("foo", conf)
	if err == nil {
		t.Fatal("initializing Ed25519 Signer/Verifier with both pub-key and pub-key-file should fail")
	}
}

func TestEd25519CanSign(t *testing.T) {
	conf := &Ed25519Config{}
	conf.PubKey = &testPubKeyEd25519Pem
	s, err := NewEd25519SignerVerifier("foo", conf)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if s.CanSign() {
		t.Fatal("initializing Ed25519 Signer/Verifier with Public-Key should not allow signing")

	}

	conf.PubKey = nil
	conf.PrivKey = &testPrivKeyEd25519Pem
	s, err = NewEd25519SignerVerifier("foo", conf)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !s.CanSign() {
		t.Fatal("initializing Ed25519 Signer/Verifier with Private-Key should allow signing")

	}
}

// TODO: add Tests for Sign() and Verify()
