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

// Package kdbcrypt encrypts and decrypts data using the KeePass1 encryption scheme.
package kdbcrypt // import "zombiezen.com/go/sandpass/pkg/kdbcrypt"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"sync"

	"golang.org/x/crypto/twofish"
	"zombiezen.com/go/sandpass/pkg/cipherio"
	"zombiezen.com/go/sandpass/pkg/padding"
)

// Errors
var (
	ErrUnknownCipher = errors.New("keepass: unknown cipher")
	ErrSize          = errors.New("keepass: data size not a multiple of 16")
)

// Block size in bytes.
const BlockSize = 16

// Params specifies the encryption/decryption values.
type Params struct {
	Key    Key
	Cipher Cipher
	IV     [16]byte
}

// A Key is the set of parameters used to build the cipher key.
type Key struct {
	Password        []byte // optional
	KeyFileHash     []byte // must be nil or length 16
	MasterSeed      [16]byte
	TransformSeed   [32]byte
	TransformRounds uint32
}

func (k *Key) build() []byte {
	sum := sha256.New()

	sum.Write(k.MasterSeed[:])

	base := k.baseHash()
	var wg sync.WaitGroup
	wg.Add(2)
	var tk [sha256.Size]byte
	go transformKeyBlock(&wg, tk[:aes.BlockSize], base[:aes.BlockSize], k.TransformSeed[:], k.TransformRounds)
	go transformKeyBlock(&wg, tk[aes.BlockSize:], base[aes.BlockSize:], k.TransformSeed[:], k.TransformRounds)
	wg.Wait()
	tk = sha256.Sum256(tk[:])
	sum.Write(tk[:])

	return sum.Sum(nil)
}

// baseHash returns the key's hash prior to encryption rounds.
func (k *Key) baseHash() [sha256.Size]byte {
	if len(k.KeyFileHash) == 0 {
		return sha256.Sum256(k.Password)
	}
	if len(k.Password) == 0 {
		var a [sha256.Size]byte
		copy(a[:], k.KeyFileHash)
		return a
	}
	h := sha256.New()
	p := sha256.Sum256(k.Password)
	h.Write(p[:])
	h.Write(k.KeyFileHash)
	var a [sha256.Size]byte
	h.Sum(a[:0])
	return a
}

// transformKeyBlock applies rounds of AES encryption using key seed to src and stores the result in dst.
func transformKeyBlock(wg *sync.WaitGroup, dst, src, seed []byte, rounds uint32) {
	dst = dst[:aes.BlockSize]
	copy(dst, src)
	c, err := aes.NewCipher(seed)
	if err != nil {
		panic(err)
	}
	for i := uint32(0); i < rounds; i++ {
		c.Encrypt(dst, dst)
	}
	wg.Done()
}

// Cipher is a cipher algorithm.
type Cipher int

// Available ciphers
const (
	RijndaelCipher Cipher = iota
	TwofishCipher
)

func (c Cipher) cipher(key []byte) (cipher.Block, error) {
	switch c {
	case RijndaelCipher:
		return aes.NewCipher(key)
	case TwofishCipher:
		return twofish.NewCipher(key)
	default:
		return nil, ErrUnknownCipher
	}
}

// NewEncrypter creates a new writer that encrypts to w.  Closing the
// new writer writes the final, padded block but does not close w.
func NewEncrypter(w io.Writer, params *Params) (io.WriteCloser, error) {
	ciph, err := params.Cipher.cipher(params.Key.build())
	if err != nil {
		return nil, err
	}
	e := cipher.NewCBCEncrypter(ciph, params.IV[:])
	return cipherio.NewWriter(w, e, padding.PKCS7), nil
}

// NewDecrypter creates a new reader that decrypts and strips padding from r.
func NewDecrypter(r io.Reader, params *Params) (io.Reader, error) {
	ciph, err := params.Cipher.cipher(params.Key.build())
	if err != nil {
		return nil, err
	}
	d := cipher.NewCBCDecrypter(ciph, params.IV[:])
	return cipherio.NewReader(r, d, padding.PKCS7), nil
}

// ReadKeyFile reads a key file and returns its hash for use in a Key.
func ReadKeyFile(r io.Reader) ([]byte, error) {
	const maxSize = 64
	data, err := ioutil.ReadAll(&io.LimitedReader{R: r, N: maxSize + 1})
	if err != nil {
		return data, err
	}
	switch len(data) {
	case 32:
		return data, nil
	case 64:
		h := make([]byte, hex.DecodedLen(len(data)))
		if _, err := hex.Decode(h, data); err == nil {
			return h, nil
		}
	}
	s := sha256.New()
	s.Write(data[:])
	if _, err := io.Copy(s, r); err != nil {
		return nil, err
	}
	return s.Sum(nil), nil
}
