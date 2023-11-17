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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type Session struct {
	Username string `json:"u"`
	Expires  int64  `json:"e"`
}

func (s *Session) Encode() []byte {
	session, _ := json.Marshal(s)
	return session
}

func (s *Session) Decode(session []byte) error {
	return json.Unmarshal(session, &s)
}

type Value struct {
	payload   []byte
	signature []byte
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
	v.signature, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid cookie value: %v", err)
	}
	return
}
