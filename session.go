// Copyright 2016 The Sandpass Authors
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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
	"zombiezen.com/go/sandpass/pkg/kdbcrypt"
	"zombiezen.com/go/sandpass/pkg/keepass"
)

// Session flags.
func init() {
	flag.StringVar(&sessions.keyPath, "session_key", "", "path to file to store session key material")
	flag.DurationVar(&sessions.keyRotation, "session_key_rotation", 12*time.Hour, "minimum duration between generating new session keys")
	flag.DurationVar(&sessions.expiry, "session_expiry", 30*time.Minute, "length of time that a session token is valid")
	sessions.now = time.Now
}

// sessionCookie is the name of browser cookie containing the session token.
const sessionCookie = "sandpass_session"

type sessionStorage struct {
	keyPath     string
	keyRotation time.Duration
	expiry      time.Duration
	now         func() time.Time
}

// new creates a new session.
func (ss *sessionStorage) new(w http.ResponseWriter, data sessionData) (*session, error) {
	keyFile, err := ss.refreshKey()
	if err != nil {
		return nil, fmt.Errorf("new session: %v", err)
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("new session: %v", err)
	}
	s := &session{
		Data: sessionData{
			Key: append([]byte(nil), data.Key...), // defensive copy
		},
		Expires: ss.now().Add(ss.expiry),
	}
	plaintext, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("new session: %v", err)
	}
	ciphertext := secretbox.Seal(nonce[:], plaintext, &nonce, keyFile.Primary.Key())
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  base64.StdEncoding.EncodeToString(ciphertext),
		Path:   "/",
		MaxAge: int(ss.expiry / time.Second),
	})
	return s, nil
}

func (ss *sessionStorage) dbFromRequest(w http.ResponseWriter, r *http.Request) (*keepass.Database, error) {
	s := ss.fromRequest(r)
	if !ss.isValid(s) {
		// Attempt to decrypt with no credentials, since that shouldn't require the
		// user to enter credentials.
		if db, err := openDatabase(nil); err == nil {
			if _, err := ss.new(w, sessionData{Key: db.ComputedKey()}); err != nil {
				return nil, err
			}
			return db, nil
		}
		return nil, errInvalidSession
	}
	return openDatabase(&keepass.Options{
		ComputedKey: s.Data.Key,
	})
}

// fromRequest obtains the request's session data. If the session information is
// in any way invalid, fromRequest returns nil. It does not return an error so
// as to potentially avoid leaking information to an attacker.
func (ss *sessionStorage) fromRequest(r *http.Request) *session {
	// Read key file before handling user input.
	keyFile, err := ss.refreshKey()
	if err != nil {
		return nil
	}
	primary := keyFile.Primary.Key()
	secondary := keyFile.Secondary.Key()
	if secondary == nil {
		secondary = primary
	}

	// Decode into binary, splitting nonce from ciphertext.
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	ciphertext, err := base64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	nonce := new([24]byte)
	if copy((*nonce)[:], ciphertext) < len(*nonce) {
		return nil
	}
	ciphertext = ciphertext[len(*nonce):]
	// Attempt to decrypt. Unconditionally unseal twice to avoid potential
	// timing attacks.
	plaintext1, ok1 := secretbox.Open(nil, ciphertext, nonce, primary)
	plaintext2, ok2 := secretbox.Open(nil, ciphertext, nonce, secondary)
	if !ok1 && !ok2 {
		return nil
	}
	var plaintext []byte
	if ok1 {
		plaintext = plaintext1
	} else {
		plaintext = plaintext2
	}
	s := new(session)
	if err := json.Unmarshal(plaintext, s); err != nil {
		return nil
	}
	if !ss.now().Before(s.Expires) {
		return nil
	}
	return s
}

func (ss *sessionStorage) isValid(s *session) bool {
	return s != nil && ss.now().Before(s.Expires)
}

// invalidateAll deletes the session keys. This effectively makes all sessions
// invalid, since they can no longer be decrypted.
func (ss *sessionStorage) invalidateAll() error {
	if err := os.Remove(ss.keyPath); err != nil {
		return fmt.Errorf("invalidate sessions: %v", err)
	}
	return nil
}

// refreshKey loads the keys from persistent storage, rotating them
// if necessary.
func (ss *sessionStorage) refreshKey() (*sessionKeyFile, error) {
	f := new(sessionKeyFile)
	if data, err := ioutil.ReadFile(ss.keyPath); err == nil {
		if err := json.Unmarshal(data, f); err != nil {
			// Don't want to proceed since we could clobber unknown data.
			return nil, fmt.Errorf("refresh session key: %v", err)
		}
	} else if !os.IsNotExist(err) {
		// Don't want to proceed since we have permissions errors.
		return nil, fmt.Errorf("refresh session key: %v", err)
	}
	now := ss.now().UTC()
	switch {
	case f.Primary.Key() == nil || !now.Before(f.Primary.Expires):
		// Primary key doesn't exist or expired.
		primary, err := newSessionKey(now.Add(ss.keyRotation))
		if err != nil {
			return nil, fmt.Errorf("refresh session key: %v", err)
		}
		f = &sessionKeyFile{Primary: primary}
	case now.After(f.Primary.Expires.Add(-ss.expiry)):
		// Sessions would be cut short by key rotation time.
		// Phase out primary to secondary ("grace period").
		newPrimary, err := newSessionKey(now.Add(ss.keyRotation))
		if err != nil {
			return nil, fmt.Errorf("refresh session key: %v", err)
		}
		secondary := new(sessionKey)
		*secondary = f.Primary
		f = &sessionKeyFile{
			Primary:   newPrimary,
			Secondary: secondary,
		}
	case f.Secondary != nil && !now.Before(f.Secondary.Expires):
		// Secondary key has expired. Clear it.
		f.Secondary = nil
	}
	newData, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("refresh session key: %v", err)
	}
	tempPath := ss.keyPath + "~"
	if err := ioutil.WriteFile(tempPath, newData, 0600); err != nil {
		return nil, fmt.Errorf("refresh session key: %v", err)
	}
	if err := os.Rename(tempPath, ss.keyPath); err != nil {
		return nil, fmt.Errorf("refresh session key: %v", err)
	}
	return f, nil
}

type sessionData struct {
	Key kdbcrypt.ComputedKey `json:"key"`
}

type session struct {
	Data    sessionData `json:"data"`
	Expires time.Time   `json:"expires"`
}

type sessionKeyFile struct {
	Primary   sessionKey  `json:"primary"`
	Secondary *sessionKey `json:"secondary,omitempty"`
}

type sessionKey struct {
	RawKey  []byte    `json:"key"`
	Expires time.Time `json:"expires"`
}

func newSessionKey(expires time.Time) (sessionKey, error) {
	k := sessionKey{
		RawKey:  make([]byte, 32),
		Expires: expires,
	}
	if _, err := rand.Read(k.RawKey); err != nil {
		return sessionKey{}, fmt.Errorf("generate session key: %v", err)
	}
	return k, nil
}

func (k *sessionKey) Key() *[32]byte {
	if k == nil || len(k.RawKey) != 32 {
		return nil
	}
	arr := new([32]byte)
	copy((*arr)[:], k.RawKey)
	return arr
}
