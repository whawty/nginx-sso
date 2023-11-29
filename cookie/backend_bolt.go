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
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	bolt "go.etcd.io/bbolt"
)

const (
	BoltSessionsBucket = "sessions"
	BoltRevokedBucket  = "revoked"
)

type BoltBackendConfig struct {
	Path string `yaml:"path"`
}

type BoltSession struct {
	SessionBase
	Agent AgentInfo `json:"agent"`
}

type BoltBackend struct {
	db *bolt.DB
}

func NewBoltBackend(conf *BoltBackendConfig) (*BoltBackend, error) {
	db, err := bolt.Open(conf.Path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		if err == bolt.ErrTimeout {
			return nil, fmt.Errorf("failed to acquire exclusive-lock for bolt-database: %s", conf.Path)
		}
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err = tx.CreateBucketIfNotExists([]byte(BoltSessionsBucket)); err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte(BoltRevokedBucket)); err != nil {
			return err
		}
		return nil
	})

	return &BoltBackend{db: db}, nil
}

func (b *BoltBackend) Name() string {
	return fmt.Sprintf("bolt(%s)", b.db.Path())
}

func (b *BoltBackend) Save(session SessionFull) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket([]byte(BoltSessionsBucket))
		if sessions == nil {
			return fmt.Errorf("database is corrupt: 'sessions' bucket does not exist!")
		}

		user, err := sessions.CreateBucketIfNotExists([]byte(session.Username))
		if err != nil {
			return fmt.Errorf("failed to create/open user-session bucket for user '%s': %v", session.Username, err)
		}

		if s := user.Get(session.ID.Bytes()); s != nil {
			return fmt.Errorf("session '%v' already exists!", session.ID)
		}

		value, err := json.Marshal(BoltSession{SessionBase: session.SessionBase, Agent: session.Agent})
		if err != nil {
			return err
		}

		return user.Put(session.ID.Bytes(), value)
	})
}

func (b *BoltBackend) ListUser(username string) (list SessionFullList, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		sessions := tx.Bucket([]byte(BoltSessionsBucket))
		if sessions == nil {
			return fmt.Errorf("database is corrupt: 'sessions' bucket does not exist!")
		}
		user := sessions.Bucket([]byte(username))
		if user == nil {
			return nil
		}

		c := user.Cursor()
		for key, value := c.First(); key != nil; key, value = c.Next() {
			var id ulid.ULID
			if err := id.UnmarshalBinary(key); err != nil {
				return err
			}
			var session BoltSession
			if err := json.Unmarshal(value, &session); err != nil {
				return err
			}
			list = append(list, SessionFull{Session: Session{ID: id, SessionBase: session.SessionBase}, Agent: session.Agent})
		}
		return nil
	})
	return
}

func (b *BoltBackend) Revoke(session Session) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket([]byte(BoltSessionsBucket))
		if sessions == nil {
			return fmt.Errorf("database is corrupt: 'sessions' bucket does not exist!")
		}

		revoked := tx.Bucket([]byte(BoltRevokedBucket))
		if revoked == nil {
			return fmt.Errorf("database is corrupt: 'revoked' bucket does not exist!")
		}

		value, err := json.Marshal(session.SessionBase)
		if err != nil {
			return err
		}

		if user := sessions.Bucket([]byte(session.Username)); user != nil {
			if err := user.Delete(session.ID.Bytes()); err != nil {
				return err
			}
		}
		return revoked.Put(session.ID.Bytes(), value)
	})
}

func (b *BoltBackend) RevokeID(username string, id ulid.ULID) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		sessions := tx.Bucket([]byte(BoltSessionsBucket))
		if sessions == nil {
			return fmt.Errorf("database is corrupt: 'sessions' bucket does not exist!")
		}
		user := sessions.Bucket([]byte(username))
		if user == nil {
			return nil
		}
		value := user.Get(id.Bytes())
		if value == nil {
			return nil
		}
		// value actually contains an encoded BoltSession, we deliberately unmarshal
		// a SessionBase to strip the AgentInfo from it
		var session SessionBase
		err := json.Unmarshal(value, &session)
		if err != nil {
			return err
		}
		if value, err = json.Marshal(session); err != nil {
			return err
		}

		revoked := tx.Bucket([]byte(BoltRevokedBucket))
		if revoked == nil {
			return fmt.Errorf("database is corrupt: 'revoked' bucket does not exist!")
		}

		if err := user.Delete(id.Bytes()); err != nil {
			return err
		}
		return revoked.Put(id.Bytes(), value)
	})
}

func (b *BoltBackend) IsRevoked(session Session) (isRevoked bool, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		revoked := tx.Bucket([]byte(BoltRevokedBucket))
		if revoked == nil {
			return fmt.Errorf("database is corrupt: 'revoked' bucket does not exist!")
		}

		value := revoked.Get(session.ID.Bytes())
		if value != nil {
			isRevoked = true
		}
		return nil
	})
	return
}

func (b *BoltBackend) ListRevoked() (list SessionList, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		revoked := tx.Bucket([]byte(BoltRevokedBucket))
		if revoked == nil {
			return fmt.Errorf("database is corrupt: 'revoked' bucket does not exist!")
		}

		c := revoked.Cursor()
		for key, value := c.First(); key != nil; key, value = c.Next() {
			var id ulid.ULID
			if err := id.UnmarshalBinary(key); err != nil {
				return err
			}
			var session SessionBase
			if err := json.Unmarshal(value, &session); err != nil {
				return err
			}
			list = append(list, Session{ID: id, SessionBase: session})
		}
		return nil
	})
	return
}

func (b *BoltBackend) LoadRevocations(list SessionList) (cnt uint, err error) {
	cnt = 0
	err = b.db.Update(func(tx *bolt.Tx) error {
		// TODO: implement this!!
		// for _, session := range list {
		// 	if _, exists := b.revoked[session.ID]; !exists {
		// 		b.revoked[session.ID] = session.SessionBase
		// 		cnt = cnt + 1
		// 	}
		// }
		return nil
	})
	return
}

func (b *BoltBackend) CollectGarbage() (cnt uint, err error) {
	cnt = 0
	err = b.db.Update(func(tx *bolt.Tx) error {
		// https://github.com/etcd-io/bbolt/issues/146#issuecomment-919299859
		// for key, value := cursor.First(); key != nil; {
		// 	if shouldDelete(v) && cursor.Delete() == nil {
		// 		key, value = cursor.Seek(key)
		// 	} else {
		// 		key, value = cursor.Next()
		// 	}
		// }

		// TODO: implement this!!
		// for _, sessions := range b.sessions {
		// 	for id, session := range sessions {
		// 		if session.IsExpired() {
		// 			delete(sessions, id)
		// 			cnt = cnt + 1
		// 		}
		// 	}
		// }
		// for id, session := range b.revoked {
		// 	if session.IsExpired() {
		// 		delete(b.revoked, id)
		// 	}
		// }
		return nil
	})
	return
}
