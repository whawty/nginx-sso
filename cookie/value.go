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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	ulidLength = len(ulid.ULID{})
)

type SessionBase struct {
	Username string `json:"u"`
	Expires  int64  `json:"e"`
}

func (s *SessionBase) SetExpiry(lifetime time.Duration) {
	s.Expires = time.Now().Add(lifetime).Unix()
}

func (s *SessionBase) IsExpired() bool {
	return time.Unix(s.Expires, 0).Before(time.Now())
}

type Value struct {
	payload   []byte
	signature []byte
}

func MakeValue(id ulid.ULID, s SessionBase) (v *Value, err error) {
	payload := make([]byte, ulidLength, 128)

	if err = id.MarshalBinaryTo(payload); err != nil {
		return
	}

	b := bytes.NewBuffer(payload)
	var encoded []byte
	if encoded, err = json.Marshal(s); err != nil {
		return
	}
	if err = json.Compact(b, encoded); err != nil {
		return
	}

	v = &Value{payload: b.Bytes()}
	return
}

func (v *Value) String() string {
	return base64.RawURLEncoding.EncodeToString(v.payload) + "." + base64.RawURLEncoding.EncodeToString(v.signature)
}

func (v *Value) FromString(encoded string) (err error) {
	parts := strings.SplitN(encoded, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid cookie value")
	}
	if parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid cookie value")
	}
	v.payload, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid cookie value: %v", err)
	}
	if len(v.payload) <= ulidLength {
		return fmt.Errorf("invalid cookie value: payload is too short")
	}
	v.signature, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid cookie value: %v", err)
	}
	return
}

func (v *Value) Session() (s SessionBase, err error) {
	err = json.Unmarshal(v.payload[ulidLength:], &s)
	return
}

func (v *Value) ID() (id ulid.ULID, err error) {
	err = id.UnmarshalBinary(v.payload[:ulidLength])
	return
}
