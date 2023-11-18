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

type MemoryBackendConfig struct {
}

type MemorySessionList map[ulid.ULID]Session

type MemoryBackend struct {
	mutex    sync.RWMutex
	sessions map[string]MemorySessionList
	revoked  map[ulid.ULID]bool
}

func NewMemoryBackend(conf *MemoryBackendConfig) (*MemoryBackend, error) {
	m := &MemoryBackend{}
	m.sessions = make(map[string]MemorySessionList)
	m.revoked = make(map[ulid.ULID]bool)
	return m, nil
}

func (b *MemoryBackend) Save(username string, id ulid.ULID, session Session) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	sessions, exists := b.sessions[username]
	if !exists {
		sessions = make(MemorySessionList)
		b.sessions[username] = sessions
	}
	if _, exists = sessions[id]; exists {
		// TODO: this probably should be a panic
		return fmt.Errorf("session with %v already exists!", id)
	}
	sessions[id] = session
	return nil
}

func (b *MemoryBackend) ListUser(username string) (list StoredSessionList, err error) {
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

func (b *MemoryBackend) Revoke(id ulid.ULID) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.revoked[id] = true
	return nil
}

func (b *MemoryBackend) IsRevoked(id ulid.ULID) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	_, exists := b.revoked[id]
	return exists, nil
}

func (b *MemoryBackend) ListRevoked() (list RevocationList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	for id, _ := range b.revoked {
		list = append(list, id)
	}
	return
}

func (b *MemoryBackend) CollectGarbage() error {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	for _, sessions := range b.sessions {
		for id, session := range sessions {
			if session.IsExpired() {
				delete(sessions, id)
				delete(b.revoked, id)
			}
		}
	}
	return nil
}
