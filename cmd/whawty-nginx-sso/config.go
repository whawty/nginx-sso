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

package main

import (
	"fmt"
	"os"

	"github.com/spreadspace/tlsconfig"
	"github.com/whawty/nginx-sso/auth"
	"github.com/whawty/nginx-sso/cookie"
	"gopkg.in/yaml.v3"
)

type LoginConfig struct {
	TemplatesPath string `yaml:"templates"`
	BasePath      string `yaml:"base-path"`
	Title         string `yaml:"title"`
}

type WebConfig struct {
	Listen string               `yaml:"listen"`
	TLS    *tlsconfig.TLSConfig `yaml:"tls"`
	Login  LoginConfig          `yaml:"login"`
}

type Config struct {
	Web    WebConfig     `yaml:"web"`
	Cookie cookie.Config `yaml:"cookie"`
	Auth   auth.Config   `yaml:"auth"`
}

func readConfig(configfile string) (*Config, error) {
	file, err := os.Open(configfile)
	if err != nil {
		return nil, fmt.Errorf("Error opening config file: %s", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)

	c := &Config{}
	if err = decoder.Decode(c); err != nil {
		return nil, fmt.Errorf("Error parsing config file: %s", err)
	}
	return c, nil
}
