// Copyright 2019 The Sandpass Authors
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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionStorage(t *testing.T) {
	start := time.Date(2019, time.July, 1, 22, 0, 0, 0, time.UTC)
	const (
		keyRotation = 12 * time.Hour
		expiry      = 30 * time.Minute
	)
	tests := []struct {
		name      string
		primeKey  bool // If true, generate a session at start time.
		createAt  time.Time
		readAt    time.Time
		deleteKey bool
		valid     bool
	}{
		{
			name:     "Fresh",
			createAt: start,
			readAt:   start.Add(1 * time.Minute),
			valid:    true,
		},
		{
			name:     "ExistingKey",
			primeKey: true,
			createAt: start.Add(1 * time.Minute),
			readAt:   start.Add(2 * time.Minute),
			valid:    true,
		},
		{
			name:     "PastExpiry",
			createAt: start,
			readAt:   start.Add(expiry),
			valid:    false,
		},
		{
			name:     "CreateBeforeGracePeriod ReadDuringGracePeriod",
			primeKey: true,
			createAt: start.Add(keyRotation - expiry - 1*time.Minute),
			readAt:   start.Add(keyRotation - 2*time.Minute),
			valid:    true,
		},
		{
			name:     "CreateDuringGracePeriod ReadAfterKeyRotation",
			primeKey: true,
			createAt: start.Add(keyRotation - expiry + 2*time.Minute),
			readAt:   start.Add(keyRotation + 1*time.Minute),
			valid:    true,
		},
		{
			name:      "KeyMissing",
			createAt:  start,
			readAt:    start.Add(1 * time.Minute),
			deleteKey: true,
			valid:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tempDir, err := ioutil.TempDir("", "sandpass-test")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.RemoveAll(tempDir); err != nil {
					t.Error(err)
				}
			}()
			now := start
			keyPath := filepath.Join(tempDir, "keys.json")
			ss := &sessionStorage{
				keyPath:     keyPath,
				keyRotation: keyRotation,
				expiry:      expiry,
				now:         func() time.Time { return now },
			}
			if test.primeKey {
				if _, err := ss.new(httptest.NewRecorder(), sessionData{}); err != nil {
					t.Fatal(err)
				}
			}

			// Create a new session.
			rec := httptest.NewRecorder()
			now = test.createAt
			_, err = ss.new(rec, sessionData{Key: []byte("Hello, World!")})
			if err != nil {
				t.Fatal(err)
			}
			cookies := rec.Result().Cookies()
			for _, c := range cookies {
				if got, want := c.MaxAge, int(expiry/time.Second); got != want {
					t.Errorf("Cookie %q has expiry of %d seconds; want %d seconds", c.Name, got, want)
				}
			}

			// Delete key if necessary.
			if test.deleteKey {
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			}

			// Try to read back session.
			now = test.readAt
			req := &http.Request{
				Header: make(http.Header),
			}
			for _, c := range cookies {
				req.AddCookie(c)
			}
			got := ss.fromRequest(req)
			if got == nil && test.valid {
				t.Error("fromRequest(req) = <nil>; want valid session")
			} else if got != nil {
				if test.valid {
					if got, want := string(got.Data.Key), "Hello, World!"; got != want {
						t.Errorf("fromRequest(req).Data.Key = %q; want %q", got, want)
					}
				} else {
					t.Errorf("fromRequest(req) = %#v; want invalid session", got)
				}
			}
		})
	}
}
