// Copyright 2016 Ross Light
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"net/http"
	"time"

	"zombiezen.com/go/sandpass/pkg/kdbcrypt"
	"zombiezen.com/go/sandpass/pkg/keepass"
)

// Session flags.
var (
	sessionExpiry = flag.Duration("session_expiry", 30*time.Minute, "length of time that a session token is valid")
	tokenSize     = flag.Int("token_size", 33, "size of the session tokens sent to the client (in bytes)")
)

// sessionCookie is the name of browser cookie containing the session token.
const sessionCookie = "sandpass_session"

type sessionStorage struct {
	s map[string]*session
}

// new creates a new session and token.
func (ss *sessionStorage) new(w http.ResponseWriter, data sessionData) *session {
	buf := make([]byte, *tokenSize)
	_, err := rand.Read(buf)
	if err != nil {
		// TODO(light): return error?
		panic(err)
	}
	tok := base64.StdEncoding.EncodeToString(buf)
	s := &session{
		token:       tok,
		expires:     time.Now().Add(*sessionExpiry),
		sessionData: data,
	}
	if ss.s == nil {
		ss.s = make(map[string]*session)
	}
	ss.s[tok] = s
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: s.token,
		Path:  "/",
	})
	return s
}

func (ss *sessionStorage) dbFromRequest(w http.ResponseWriter, r *http.Request) (*keepass.Database, error) {
	s := ss.fromRequest(r)
	if !s.isValid() {
		// Attempt to decrypt with no credentials, since that shouldn't require the
		// user to enter credentials.
		if db, err := openDatabase(nil); err == nil {
			ss.new(w, sessionData{key: db.ComputedKey()})
			return db, nil
		}
		return nil, errInvalidSession
	}
	return openDatabase(&keepass.Options{
		ComputedKey: s.key,
	})
}

func (ss *sessionStorage) fromRequest(r *http.Request) *session {
	if ss.s == nil {
		return nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	return ss.s[c.Value]
}

func (ss *sessionStorage) clear() {
	for id, s := range ss.s {
		s.clear()
		delete(ss.s, id)
	}
}

func (ss *sessionStorage) clearInvalid() int {
	n := 0
	for id, s := range ss.s {
		if !s.isValid() {
			s.clear()
			delete(ss.s, id)
			n++
		}
	}
	return n
}

type sessionData struct {
	key kdbcrypt.ComputedKey
}

// clear zeroes out the session's data as a weak defense against RAM compromise.
func (data *sessionData) clear() {
	for i := range data.key {
		data.key[i] = 0
	}
}

type session struct {
	sessionData
	token   string
	expires time.Time
}

func (s *session) isValid() bool {
	return s != nil && time.Now().Before(s.expires)
}
