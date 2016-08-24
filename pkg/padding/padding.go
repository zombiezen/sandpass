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

// Package padding provides functions to handle padding in block ciphers.
package padding // import "zombiezen.com/go/sandpass/pkg/padding"

import "errors"

// Padding is a padding algorithm.
type Padding interface {
	// Pad appends padding to b to align it to a block size.
	// The block size must be greater than 1.
	Pad(b []byte, blockSize int) []byte

	// Strip removes the padding from b.  The resulting slice will always
	// be a subslice of the argument.  The block size must be greater than 1.
	Strip(b []byte, blockSize int) ([]byte, error)
}

// Errors
var (
	ErrWrongPadding = errors.New("wrong padding")
	ErrBadBlockSize = errors.New("bad block size")
	ErrDataSize     = errors.New("input is not a multiple of block size")
)

// PKCS7 implements the padding algorithm as described in
// PKCS #7 section 10.3.  The block size must be less than 256.
var PKCS7 Padding = pkcs7{}

type pkcs7 struct{}

func (pkcs7) String() string {
	return "PKCS7"
}

func (pkcs7) GoString() string {
	return "padding.PKCS7"
}

func (pkcs7) Pad(b []byte, blockSize int) []byte {
	if blockSize <= 1 || blockSize >= 256 {
		panic("padding: illegal PKCS7 block size")
	}
	pad := blockSize - len(b)%blockSize
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}

func (pkcs7) Strip(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 1 || blockSize >= 256 {
		return b, ErrBadBlockSize
	}
	n := len(b)
	if n%blockSize != 0 {
		return b, ErrDataSize
	}
	pad := int(b[n-1])
	if pad == 0 || pad > blockSize {
		return b, ErrWrongPadding
	}
	for _, x := range b[n-pad : n-1] {
		if x != byte(pad) {
			return b, ErrWrongPadding
		}
	}
	return b[:n-pad], nil
}
