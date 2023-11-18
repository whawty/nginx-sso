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

type InMemorySessionList map[ulid.ULID]Session

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

func (b *InMemoryBackend) Save(username string, id ulid.ULID, session Session) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	sessions, exists := b.sessions[username]
	if !exists {
		sessions = make(InMemorySessionList)
		b.sessions[username] = sessions
	}
	if _, exists = sessions[id]; exists {
		// TODO: this probably should be a panic
		return fmt.Errorf("session '%v' already exists!", id)
	}
	sessions[id] = session
	return nil
}

func (b *InMemoryBackend) ListUser(username string) (list StoredSessionList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	sessions, exists := b.sessions[username]
	if !exists {
		return
	}
	for id, session := range sessions {
		list = append(list, StoredSession{ID: id, Session: session})
	}
	return
}

func (b *InMemoryBackend) Revoke(username string, id ulid.ULID) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	sessions, exists := b.sessions[username]
	if !exists {
		return fmt.Errorf("session '%v' does not exist", id)
	}
	session, exists := sessions[id]
	if !exists {
		return fmt.Errorf("session '%v' does not exist", id)
	}
	delete(sessions, id)
	b.revoked[id] = session
	return nil
}

func (b *InMemoryBackend) IsRevoked(id ulid.ULID) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	_, exists := b.revoked[id]
	return exists, nil
}

func (b *InMemoryBackend) ListRevoked() (list StoredSessionList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	for id, session := range b.revoked {
		list = append(list, StoredSession{ID: id, Session: session})
	}
	return
}

func (b *InMemoryBackend) CollectGarbage() error {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	for _, sessions := range b.sessions {
		for id, session := range sessions {
			if session.IsExpired() {
				delete(sessions, id)
			}
		}
	}
	for id, session := range b.revoked {
		if session.IsExpired() {
			delete(b.revoked, id)
		}
	}

	return nil
}
