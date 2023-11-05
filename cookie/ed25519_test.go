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
	testPubKeyPem = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAY/jnaras6sQc+ggSVhh7o/kJsCLr1D6tbaRZ8+kY8IY=
-----END PUBLIC KEY-----
`
	testPubKeyBytes = ed25519.PublicKey{0x63, 0xf8, 0xe7, 0x6a, 0xb6, 0xac, 0xea, 0xc4, 0x1c, 0xfa, 0x8, 0x12, 0x56, 0x18, 0x7b, 0xa3, 0xf9, 0x9, 0xb0, 0x22, 0xeb, 0xd4, 0x3e, 0xad, 0x6d, 0xa4, 0x59, 0xf3, 0xe9, 0x18, 0xf0, 0x86}
)

func TestLoadEd25519PublicKey(t *testing.T) {
	conf := &Ed25519Config{}
	conf.PubKey = &testPubKeyPem

	pub, err := loadEd25519PublicKey(conf)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	if bytes.Compare(pub, testPubKeyBytes) != 0 {
		t.Fatalf("encoding cookie payload failed, expected: '%#v', got '%#v'", testPubKeyBytes, pub)
	}
}
