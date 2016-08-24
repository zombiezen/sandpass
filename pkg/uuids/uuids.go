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

// Package uuids provides functions for generating and handling UUIDs
// as defined by RFC 4122.
package uuids // import "zombiezen.com/go/sandpass/pkg/uuids"

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strconv"
)

// Namespaces
var (
	DNS  = UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	URL  = UUID{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	OID  = UUID{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	X500 = UUID{0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
)

// A UUID is a universally unique identifier: a 128-bit value.
type UUID [16]byte

// Parse parses a hex-encoded UUID string (that may contain dashes) into a UUID.
func Parse(s string) (UUID, error) {
	b := []byte(s)
	n := 0
	for i := 0; i < len(b); i++ {
		if b[i] != '-' {
			b[n] = b[i]
			n++
		}
	}
	b = b[:n]
	var u UUID
	if len(b) != hex.EncodedLen(len(u)) {
		return UUID{}, parseError{s, errSize}
	}
	_, err := hex.Decode(u[:], b)
	if err != nil {
		return UUID{}, parseError{s, err}
	}
	return u, nil
}

var errSize = errors.New("wrong size")

type parseError struct {
	s   string
	err error
}

func (e parseError) Error() string {
	return "uuid: failed to parse " + strconv.Quote(e.s) + ": " + e.err.Error()
}

// New3 creates a UUID (version 3) based on the MD5 hash of the
// namespace and ID given.
func New3(namespace UUID, id []byte) UUID {
	return newHash(md5.New(), 3, namespace, id)
}

// New4 generates a new UUID (version 4) using a provided source of
// random bytes.  If r is nil, crypto/rand.Reader is used.
func New4(r io.Reader) (UUID, error) {
	if r == nil {
		r = rand.Reader
	}
	var u UUID
	if _, err := io.ReadFull(r, u[:]); err != nil {
		return UUID{}, err
	}
	u = setVersion(u, 4)
	return u, nil
}

// New5 creates a UUID (version 5) based on the SHA-1 hash of the
// namespace and ID given.
func New5(namespace UUID, id []byte) UUID {
	return newHash(sha1.New(), 5, namespace, id)
}

func newHash(h hash.Hash, vers int, namespace UUID, id []byte) UUID {
	if h.Size() < 16 {
		panic("newHash called with small hash algorithm")
	}
	h.Write(namespace[:])
	h.Write(id)
	sum := h.Sum(nil)
	var u UUID
	copy(u[:], sum)
	u = setVersion(u, vers)
	return u
}

func setVersion(u UUID, vers int) UUID {
	u[8] = u[8]&^0xc0 | 0x80
	u[6] = u[6]&^0xf0 | byte(vers)<<4
	return u
}

// AppendHex appends the dash-separated hex representation of u to b
// and returns the extended buffer.
func (u UUID) AppendHex(b []byte) []byte {
	b = appendHex(b, u[:4])
	b = append(b, '-')
	b = appendHex(b, u[4:6])
	b = append(b, '-')
	b = appendHex(b, u[6:8])
	b = append(b, '-')
	b = appendHex(b, u[8:10])
	b = append(b, '-')
	b = appendHex(b, u[10:])
	return b
}

func appendHex(b, src []byte) []byte {
	i := len(b)
	n := hex.EncodedLen(len(src))
	for j := 0; j < n; j++ {
		b = append(b, 0)
	}
	hex.Encode(b[i:], src)
	return b
}

// IsZero reports whether this is the zero UUID.
func (u UUID) IsZero() bool {
	return u == UUID{}
}

// String returns the dash-separated hex representation of u as a string.
func (u UUID) String() string {
	b := make([]byte, 0, 36)
	b = u.AppendHex(b)
	return string(b)
}

func (u UUID) variant() uint8 {
	return u[8] >> 5
}

func (u UUID) isRFCVariant() bool {
	return u.variant()&6 == 4
}

// Version returns u's version or zero if this is not the RFC-specified UUID variant.
func (u UUID) Version() int {
	if !u.isRFCVariant() {
		return 0
	}
	return int(u[6] >> 4)
}
