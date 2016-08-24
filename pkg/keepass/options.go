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

package keepass

import (
	"crypto/rand"
	"io"

	"zombiezen.com/go/sandpass/pkg/kdbcrypt"
)

// Options is the set of parameters for creating or opening a database.
// Nil is treated the same as the zero value.
type Options struct {
	// Password is an optional textual password to encrypt/decrypt
	// the database.
	Password string

	// KeyFile is an optional binary file to encrypt/decrypt the database.
	KeyFile io.Reader

	// If ComputedKey is non-nil, it will be used instead of Password/KeyFile
	// to decrypt an existing database.
	ComputedKey kdbcrypt.ComputedKey

	// Random number source, used for salts and ID generation.
	// Defaults to crypto/rand.Reader.
	Rand io.Reader

	// Number of rounds to encrypt the key with.  Higher values mean key
	// generation takes longer, thus harder to brute force.  If zero,
	// a reasonable default is used.  Only used for creation.
	KeyRounds int

	// Cipher to encrypt with.  Defaults to AES-256 (RijndaelCipher).
	// Only used for creation.
	Cipher kdbcrypt.Cipher

	// StaticIVForTesting will keep the IV the same between writes, useful
	// for testing, but insecure. Never enable this in production code!
	StaticIVForTesting bool
}

// initCryptParams creates kdbcrypt parameters for a new database.
func (opts *Options) initCryptParams(p *kdbcrypt.Params) error {
	p.Cipher = opts.getCipher()
	r := reader{r: opts.getRand()}
	if opts.staticIV() {
		r.readFull(p.IV[:])
		// Error checked after seeds, since this is uncommon to set in prod.
	}
	var err error
	p.Key.KeyFileHash, err = opts.getKeyFileHash()
	if err != nil {
		return err
	}
	p.Key.Password = []byte(opts.getPassword())
	p.Key.TransformRounds = uint32(opts.getKeyRounds())
	r.readFull(p.Key.MasterSeed[:])
	r.readFull(p.Key.TransformSeed[:])
	if r.err != nil {
		return r.err
	}
	p.ComputedKey = p.Key.Compute()
	return nil
}

func (opts *Options) getPassword() string {
	if opts == nil {
		return ""
	}
	return opts.Password
}

func (opts *Options) getKeyFileHash() ([]byte, error) {
	if opts == nil || opts.KeyFile == nil {
		return nil, nil
	}
	return kdbcrypt.ReadKeyFile(opts.KeyFile)
}

func (opts *Options) getRand() io.Reader {
	if opts == nil || opts.Rand == nil {
		return rand.Reader
	}
	return opts.Rand
}

func (opts *Options) getKeyRounds() uint32 {
	if opts == nil || opts.KeyRounds <= 0 {
		// 1 second delay on Intel i7-2600K CPU @ 3.40GHz
		return 10000000
	}
	return uint32(opts.KeyRounds)
}

func (opts *Options) getCipher() kdbcrypt.Cipher {
	if opts == nil {
		// Return the default cipher
		return 0
	}
	return opts.Cipher
}

func (opts *Options) staticIV() bool {
	return opts != nil && opts.StaticIVForTesting
}

// Ciphers for Options
const (
	RijndaelCipher = kdbcrypt.RijndaelCipher
	TwofishCipher  = kdbcrypt.TwofishCipher
)
