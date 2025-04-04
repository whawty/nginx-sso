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
	"github.com/prometheus/client_golang/prometheus"
)

type InMemoryBackendConfig struct {
}

type InMemorySession struct {
	SessionBase
	Agent AgentInfo `json:"agent"`
}

type InMemorySessionMap map[ulid.ULID]InMemorySession

type InMemoryBackend struct {
	mutex    sync.RWMutex
	sessions map[string]InMemorySessionMap
	revoked  map[ulid.ULID]SessionBase
}

func NewInMemoryBackend(conf *InMemoryBackendConfig, prom prometheus.Registerer) (*InMemoryBackend, error) {
	m := &InMemoryBackend{}
	m.sessions = make(map[string]InMemorySessionMap)
	m.revoked = make(map[ulid.ULID]SessionBase)
	if prom != nil {
		if err := m.initPrometheus(prom); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (b *InMemoryBackend) initPrometheus(prom prometheus.Registerer) error {
	// TODO: implement this!
	return nil
}

func (b *InMemoryBackend) Name() string {
	return "in-memory"
}

func (b *InMemoryBackend) Save(session SessionFull) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	sessions, exists := b.sessions[session.Username]
	if !exists {
		sessions = make(InMemorySessionMap)
		b.sessions[session.Username] = sessions
	}
	if _, exists = sessions[session.ID]; exists {
		return fmt.Errorf("session '%v' already exists", session.ID)
	}
	sessions[session.ID] = InMemorySession{SessionBase: session.SessionBase, Agent: session.Agent}
	return nil
}

func (b *InMemoryBackend) ListUser(username string) (list SessionFullList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	sessions, exists := b.sessions[username]
	if !exists {
		return
	}
	for id, session := range sessions {
		if !session.IsExpired() {
			list = append(list, SessionFull{Session: Session{ID: id, SessionBase: session.SessionBase}, Agent: session.Agent})
		}
	}
	return
}

func (b *InMemoryBackend) Revoke(session Session) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if sessions, exists := b.sessions[session.Username]; exists {
		delete(sessions, session.ID)
	}
	b.revoked[session.ID] = session.SessionBase
	return nil
}

func (b *InMemoryBackend) RevokeID(username string, id ulid.ULID) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	sessions, exists := b.sessions[username]
	if !exists {
		return nil
	}
	session, exists := sessions[id]
	if !exists {
		return nil
	}
	delete(sessions, id)
	b.revoked[id] = session.SessionBase
	return nil
}

func (b *InMemoryBackend) IsRevoked(session Session) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	_, exists := b.revoked[session.ID]
	return exists, nil
}

func (b *InMemoryBackend) ListRevoked() (list SessionList, err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	for id, session := range b.revoked {
		if !session.IsExpired() {
			list = append(list, Session{ID: id, SessionBase: session})
		}
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
