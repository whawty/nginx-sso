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
	"reflect"
	"testing"
)

func TestSessionEncode(t *testing.T) {
	var s Session
	s.Username = "test"
	s.Expires = 1000

	expected := []byte("{\"u\":\"test\",\"e\":1000}\n") // TODO: json.Encoder always adds a new-line....
	b := &bytes.Buffer{}
	if err := s.Encode(b); err != nil {
		t.Fatal("unexpected error:", err)
	}
	encoded := b.Bytes()
	if bytes.Compare(expected, encoded) != 0 {
		t.Fatalf("encoding cookie session failed, expected: '%s', got '%s'", expected, encoded)
	}
}

func TestSessionDecode(t *testing.T) {
	encoded := []byte("{\"u\":\"test\",\"e\":1000}")
	var expected Session
	expected.Username = "test"
	expected.Expires = 1000

	var decoded Session
	err := decoded.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !reflect.DeepEqual(decoded, expected) {
		t.Fatalf("decoding cookie session failed, expected: '%+v', got '%+v'", expected, decoded)
	}
}

func TestValueToString(t *testing.T) {
	var v Value
	v.payload = []byte("{\"u\":\"test\",\"e\":1000}")
	v.signature = []byte("this-is-not-a-signature")

	encoded := v.String()
	expected := "eyJ1IjoidGVzdCIsImUiOjEwMDB9.dGhpcy1pcy1ub3QtYS1zaWduYXR1cmU"

	if expected != encoded {
		t.Fatalf("encoding cookie value failed, expected: '%s', got '%s'", expected, encoded)
	}
}

func TestValueFromString(t *testing.T) {
	vectors := []struct {
		encoded string
		valid   bool
	}{
		{"", false},
		{"foo", false},
		{"", false},
		{".", false},
		{".bar", false},
		{"foo.", false},
		{"foo.bar", true},
		{"foo.bar.blub", false},
		{"foo/bar.blub", false},
		{"foo+bar.blub", false},
		{"foo.bar/blub", false},
		{"foo.bar+blub", false},
		{"foo.bar=", false},
		{"foo=.bar", false},
	}
	for _, vector := range vectors {
		var v Value
		err := v.FromString(vector.encoded)
		if vector.valid {
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
		} else {
			if err == nil {
				t.Fatalf("decoding cookie value from string '%s' should fail", vector.encoded)
			}
		}
	}

	encoded := "eyJ1IjoidGVzdCIsImUiOjEwMDB9.dGhpcy1pcy1ub3QtYS1zaWduYXR1cmU"
	expectedSignature := []byte("this-is-not-a-signature")
	expectedSession := Session{Username: "test", Expires: 1000}

	var v Value
	err := v.FromString(encoded)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if bytes.Compare(v.signature, expectedSignature) != 0 {
		t.Fatalf("encoding cookie session failed, expected: '%s', got '%s'", expectedSignature, v.signature)
	}
	var s Session
	err = s.Decode(bytes.NewReader(v.payload))
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !reflect.DeepEqual(s, expectedSession) {
		t.Fatalf("decoding cookie session failed, expected: '%+v', got '%+v'", expectedSession, s)
	}
}
