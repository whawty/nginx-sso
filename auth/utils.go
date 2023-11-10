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

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

func loadFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

func serverNameFromUrl(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("server url '%s' is invalid", server)
	}
	return u.Hostname(), nil
}

type TLSClientConfig struct {
	StartTLS           bool     `yaml:"start-tls"`
	InsecureSkipVerify bool     `yaml:"insecure-skip-verify"`
	CACertificates     string   `yaml:"ca-certificates"`
	CACertificateFiles []string `yaml:"ca-certificate-files"`
}

func (t TLSClientConfig) ToGoTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{}

	cfg = &tls.Config{}
	cfg.InsecureSkipVerify = t.InsecureSkipVerify
	cfg.RootCAs = x509.NewCertPool()
	if t.CACertificates != "" {
		if ok := cfg.RootCAs.AppendCertsFromPEM([]byte(t.CACertificates)); !ok {
			return nil, fmt.Errorf("no certificates found in ca-certificates content")
		}
	}
	for _, cert := range t.CACertificateFiles {
		pemData, err := loadFile(cert)
		if err != nil {
			return nil, fmt.Errorf("loading ca-certificate file failed: %v", err)
		}

		ok := cfg.RootCAs.AppendCertsFromPEM(pemData)
		if !ok {
			return nil, fmt.Errorf("no ca-certificates found in file '%s'", cert)
		}
	}
	return cfg, nil
}

type watchFileErrorCB func(error)
type watchFileEventCB func(fsnotify.Event)

func watchFileLoop(w *fsnotify.Watcher, files []string, errorCB watchFileErrorCB, eventCB watchFileEventCB) {
	for {
		select {
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			errorCB(err)
		case event, ok := <-w.Events:
			if !ok {
				return
			}

			for _, file := range files {
				if file == event.Name {
					eventCB(event)
					break
				}
			}
		}
	}
}

func runFileWatcher(files []string, errorCB watchFileErrorCB, eventCB watchFileEventCB) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	go watchFileLoop(w, files, errorCB, eventCB)

	for _, file := range files {
		st, err := os.Lstat(file)
		if err != nil {
			return err
		}
		if st.IsDir() {
			return fmt.Errorf("'%s' is a directory, not a file", file)
		}

		if err = w.Add(filepath.Dir(file)); err != nil {
			return err
		}
	}
	return nil
}
