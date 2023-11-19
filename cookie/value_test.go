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

	"github.com/oklog/ulid/v2"
)

func TestMakeValue(t *testing.T) {
	testID := ulid.MustParseStrict("0024H36H2NCSVRH6DAQF6DVVQZ")
	testSession := SessionBase{Username: "test", Expires: 1000}
	testSessionEncoded := []byte("{\"u\":\"test\",\"e\":1000}")
	expectedPayload := append(testID.Bytes(), testSessionEncoded...)

	v, err := MakeValue(testID, testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if bytes.Compare(v.payload, expectedPayload) != 0 {
		t.Fatalf("encoding cookie payload failed, expected: '%s', got '%s'", expectedPayload, v.payload)
	}
}

func TestValueToString(t *testing.T) {
	testID := ulid.MustParseStrict("0024H36H2NCSVRH6DAQF6DVVQZ")
	testSession := SessionBase{Username: "test", Expires: 1000}
	v, err := MakeValue(testID, testSession)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	v.signature = []byte("this-is-not-a-signature")

	encoded := v.String()
	expected := "ABEiM0RVZneImaq7zN3u_3sidSI6InRlc3QiLCJlIjoxMDAwfQ.dGhpcy1pcy1ub3QtYS1zaWduYXR1cmU"

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
		{".", false},
		{".bar", false},
		{"foo.", false},
		{"foo.bar", false},
		{"fooooooooooooooooooooo.bar", false},
		{"foooooooooooooooooooooo.bar", true},
		{"foooooooooooooooooooooo.bar.blub", false},
		{"foooooooooooooooooooooo/bar.blub", false},
		{"foooooooooooooooooooooo+bar.blub", false},
		{"foooooooooooooooooooooo.bar/blub", false},
		{"foooooooooooooooooooooo.bar+blub", false},
		{"foooooooooooooooooooooo.bar=", false},
		{"foooooooooooooooooooooo=.bar", false},
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

	encoded := "ABEiM0RVZneImaq7zN3u_3sidSI6InRlc3QiLCJlIjoxMDAwfQ.dGhpcy1pcy1ub3QtYS1zaWduYXR1cmU"
	expectedSignature := []byte("this-is-not-a-signature")
	expectedSession := SessionBase{Username: "test", Expires: 1000}
	expectedID := ulid.MustParseStrict("0024H36H2NCSVRH6DAQF6DVVQZ")

	var v Value
	err := v.FromString(encoded)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if bytes.Compare(v.signature, expectedSignature) != 0 {
		t.Fatalf("encoding cookie session failed, expected: '%s', got '%s'", expectedSignature, v.signature)
	}

	s, err := v.Session()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if !reflect.DeepEqual(s, expectedSession) {
		t.Fatalf("decoding cookie session failed, expected: '%+v', got '%+v'", expectedSession, s)
	}

	id, err := v.ID()
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if id.Compare(expectedID) != 0 {
		t.Fatalf("decoding cookie id failed, expected: '%v', got '%v'", expectedID, id)
	}
}
