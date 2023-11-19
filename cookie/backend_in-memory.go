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
	"fmt"
	"sync"

	"github.com/oklog/ulid/v2"
)

type InMemoryBackendConfig struct {
}

type InMemorySessionList map[ulid.ULID]SessionBase

type InMemoryBackend struct {
	mutex    sync.RWMutex
	sessions map[string]InMemorySessionList
	revoked  InMemorySessionList
}

func NewInMemoryBackend(conf *InMemoryBackendConfig) (*InMemoryBackend, error) {
	m := &InMemoryBackend{}
	m.sessions = make(map[string]InMemorySessionList)
	m.revoked = make(InMemorySessionList)
	return m, nil
}

func (b *InMemoryBackend) Save(id ulid.ULID, session SessionBase) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	sessions, exists := b.sessions[session.Username]
	if !exists {
		sessions = make(InMemorySessionList)
		b.sessions[session.Username] = sessions
	}
	if _, exists = sessions[id]; exists {
		return fmt.Errorf("session '%v' already exists!", id)
	}
	sessions[id] = session
	return nil
}

func (b *InMemoryBackend) ListUser(username string) (list SessionList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	sessions, exists := b.sessions[username]
	if !exists {
		return
	}
	for id, session := range sessions {
		if _, revoked := b.revoked[id]; !revoked {
			list = append(list, Session{ID: id, SessionBase: session})
		}
	}
	return
}

func (b *InMemoryBackend) Revoke(id ulid.ULID, session SessionBase) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.revoked[id] = session
	return nil
}

func (b *InMemoryBackend) IsRevoked(id ulid.ULID) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	_, exists := b.revoked[id]
	return exists, nil
}

func (b *InMemoryBackend) ListRevoked() (list SessionList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	for id, session := range b.revoked {
		list = append(list, Session{ID: id, SessionBase: session})
	}
	return
}

func (b *InMemoryBackend) LoadRevocations(list SessionList) (cnt uint, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	cnt = 0
	for _, session := range list {
		if _, exists := b.revoked[session.ID]; !exists {
			b.revoked[session.ID] = session.SessionBase
			cnt = cnt + 1
		}
	}
	return
}

func (b *InMemoryBackend) CollectGarbage() (uint, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	cnt := uint(0)
	for _, sessions := range b.sessions {
		for id, session := range sessions {
			if session.IsExpired() {
				delete(sessions, id)
				cnt = cnt + 1
			}
		}
	}
	for id, session := range b.revoked {
		if session.IsExpired() {
			delete(b.revoked, id)
		}
	}

	return cnt, nil
}
