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

// Package sandstormhdr reads Sandstorm information from HTTP request headers.
package sandstormhdr

import (
	"log"
	"net/http"
	"strconv"
)

// A User represents a Sandstorm user.
type User struct {
	// ID is a globally unique identifier for the user.
	ID string

	// Name is the user's display name.
	Name string

	// PreferredHandle is a handle, consisting of ASCII letters, numbers, and underscores.
	Handle string

	// PictureURL is a URL to a 64x64 profile picture.
	PictureURL string

	// Pronouns is the user's preferred pronouns.
	// One of "neutral", "male", "female", or "robot".
	Pronouns string
}

// String returns the user's display name.
func (u *User) String() string {
	return u.Name
}

// GetUser extracts the user information from a request header
// or nil if the user is not logged in.
func GetUser(h http.Header) *User {
	id := h.Get("X-Sandstorm-User-Id")
	if id == "" {
		return nil
	}
	return &User{
		ID:         id,
		Name:       UserName(h),
		Handle:     h.Get("X-Sandstorm-Preferred-Handle"),
		PictureURL: h.Get("X-Sandstorm-User-Picture"),
		Pronouns:   h.Get("X-Sandstorm-User-Pronouns"),
	}
}

// UserName extracts the user's display name from a request header.
// This may be non-empty even if the user is not logged in.
func UserName(h http.Header) string {
	const hdrName = "X-Sandstorm-Username"
	name, err := unescape(h.Get(hdrName))
	if err != nil {
		log.Printf("sandstormhdr: failed to parse %s: %v", hdrName, err)
		return ""
	}
	return name
}

// Permissions extracts the permissions in the request header.
func Permissions(h http.Header) []string {
	p := h.Get("X-Sandstorm-Permissions")
	if p == "" {
		return nil
	}
	return splitComma(p)
}

// HasPermission reports whether the request header contains a permission.
func HasPermission(h http.Header, perm string) bool {
	ps := Permissions(h)
	for _, p := range ps {
		if p == perm {
			return true
		}
	}
	return false
}

// SessionID returns the session identifier.
func SessionID(h http.Header) string {
	return h.Get("X-Sandstorm-Session-Id")
}

func unescape(s string) (string, error) {
	// Count %, check that they're well-formed.
	n := 0
	for i := 0; i < len(s); {
		if s[i] == '%' {
			n++
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[0:3]
				}
				return "", escapeError(s)
			}
			i += 3
		} else {
			i++
		}
	}

	if n == 0 {
		return s, nil
	}

	t := make([]byte, len(s)-2*n)
	j := 0
	for i := 0; i < len(s); {
		if s[i] == '%' {
			t[j] = unhex(s[i+1])<<4 | unhex(s[i+2])
			j++
			i += 3
		} else {
			t[j] = s[i]
			j++
			i++
		}
	}
	return string(t), nil
}

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func splitComma(s string) []string {
	n := 1
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			n++
		}
	}
	a := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			a = append(a, s[start:i])
			start = i + 1
		}
	}
	a = append(a, s[start:])
	return a
}

type escapeError string

func (e escapeError) Error() string {
	return "invalid URL escape " + strconv.Quote(string(e))
}
