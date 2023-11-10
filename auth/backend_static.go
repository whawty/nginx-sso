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
	"fmt"
	"log"

	"github.com/fsnotify/fsnotify"
	"github.com/tg123/go-htpasswd"
)

type StaticConfig struct {
	HTPasswd string `yaml:"htpasswd"`
}

type StaticBackend struct {
	htpasswd *htpasswd.File
	infoLog  *log.Logger
	dbgLog   *log.Logger
}

func NewStaticBackend(conf *StaticConfig, infoLog, dbgLog *log.Logger) (Backend, error) {
	file, err := htpasswd.New(conf.HTPasswd, htpasswd.DefaultSystems, func(err error) {
		dbgLog.Printf("static: found invalid line: %v", err)
	})
	if err != nil {
		infoLog.Printf("static: failed to initialize database: %v", err)
		return nil, err
	}

	b := &StaticBackend{htpasswd: file, infoLog: infoLog, dbgLog: dbgLog}
	runFileWatcher([]string{conf.HTPasswd}, b.watchFileErrorCB, b.watchFileEventCB)
	infoLog.Printf("static: successfully initilized database: %s", conf.HTPasswd)
	return b, nil
}

func (b *StaticBackend) watchFileErrorCB(err error) {
	b.infoLog.Printf("static: got error from fsnotify watcher: %v", err)
}

func (b *StaticBackend) watchFileEventCB(event fsnotify.Event) {
	err := b.htpasswd.Reload(func(err error) {
		b.dbgLog.Printf("static: found invalid line: %v", err)
	})
	if err != nil {
		b.infoLog.Printf("static: reloading htpasswd file failed: %v, keeping current database", err)
		return
	}
	b.dbgLog.Printf("static: htpasswd file successfully reloaded")
}

func (b *StaticBackend) Authenticate(username, password string) error {
	ok := b.htpasswd.Match(username, password)
	if !ok {
		return fmt.Errorf("invalid username or password")
	}
	return nil
}
