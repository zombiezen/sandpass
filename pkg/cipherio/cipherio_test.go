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

package cipherio

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"testing/iotest"

	"zombiezen.com/go/sandpass/pkg/padding"
)

// A cipherTest is a single test case of a reader or writer.
// The block cipher mode is assumed to encrypt by adding one to all bytes.
// Each test case may be used multiple times to test different reader/writer conditions.
type cipherTest struct {
	plain     []byte
	cipher    []byte
	blockSize int
	readErr   error
}

var tests = []cipherTest{
	{
		plain:     []byte{},
		cipher:    []byte{},
		blockSize: 4,
		readErr:   io.ErrUnexpectedEOF,
	},
	{
		plain:     []byte{},
		cipher:    []byte{1},
		blockSize: 4,
		readErr:   io.ErrUnexpectedEOF,
	},
	{
		plain:     []byte{},
		cipher:    []byte{5, 5, 5, 5},
		blockSize: 4,
	},
	{
		plain:     []byte{42},
		cipher:    []byte{43, 4, 4, 4},
		blockSize: 4,
	},
	{
		plain:     []byte{0, 1, 2, 3},
		cipher:    []byte{1, 2, 3, 4, 5, 5, 5, 5},
		blockSize: 4,
	},
	{
		plain:     []byte{0, 1, 2, 3, 42},
		cipher:    []byte{1, 2, 3, 4, 43, 4, 4, 4},
		blockSize: 4,
	},
	{
		plain:     []byte{0, 1, 2, 3, 4, 5, 6, 7},
		cipher:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 5, 5, 5, 5},
		blockSize: 4,
	},
	{
		plain:     []byte{0, 1, 2, 3, 4, 5, 6, 7, 42},
		cipher:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 43, 4, 4, 4},
		blockSize: 4,
	},
}

func TestReader(t *testing.T) {
	for _, test := range tests {
		plain := new(bytes.Buffer)
		mode := fakeBlockMode{size: test.blockSize, delta: 255}

		r := NewReader(bytes.NewReader(test.cipher), mode, padding.PKCS7)
		_, err := io.Copy(plain, r)

		subject := fmt.Sprintf("io.Copy(..., NewReader(bytes.NewReader(%v), %#v, padding.PKCS7))", test.cipher, mode)
		if err != test.readErr {
			t.Errorf("%s error = %v; want %v", subject, err, test.readErr)
		}
		if !bytes.Equal(plain.Bytes(), test.plain) {
			t.Errorf("%s data = %v; want %v", subject, plain.Bytes(), test.plain)
		}
	}
}

func TestReader_OneByteInput(t *testing.T) {
	for _, test := range tests {
		plain := new(bytes.Buffer)
		mode := fakeBlockMode{size: test.blockSize, delta: 255}
		src := iotest.OneByteReader(bytes.NewReader(test.cipher))

		r := NewReader(src, mode, padding.PKCS7)
		_, err := io.Copy(plain, r)

		subject := fmt.Sprintf("io.Copy(..., NewReader(iotest.OneByteReader(bytes.NewReader(%v)), %#v, padding.PKCS7))", test.cipher, mode)
		if err != test.readErr {
			t.Errorf("%s error = %v; want %v", subject, err, test.readErr)
		}
		if !bytes.Equal(plain.Bytes(), test.plain) {
			t.Errorf("%s data = %v; want %v", subject, plain.Bytes(), test.plain)
		}
	}
}

func TestReader_OneByteOutput(t *testing.T) {
	for _, test := range tests {
		plain := new(bytes.Buffer)
		mode := fakeBlockMode{size: test.blockSize, delta: 255}

		r := iotest.OneByteReader(NewReader(bytes.NewReader(test.cipher), mode, padding.PKCS7))
		_, err := io.Copy(plain, r)

		subject := fmt.Sprintf("io.Copy(..., iotest.OneByteReader(NewReader(bytes.NewReader(%v)), %#v, padding.PKCS7))", test.cipher, mode)
		if err != test.readErr {
			t.Errorf("%s error = %v; want %v", subject, err, test.readErr)
		}
		if !bytes.Equal(plain.Bytes(), test.plain) {
			t.Errorf("%s data = %v; want %v", subject, plain.Bytes(), test.plain)
		}
	}
}

func TestWriter(t *testing.T) {
	for _, test := range tests {
		if test.readErr != nil {
			continue
		}
		cipher := new(bytes.Buffer)
		mode := fakeBlockMode{size: test.blockSize, delta: 1}

		w := NewWriter(cipher, mode, padding.PKCS7)
		_, err := io.Copy(w, bytes.NewReader(test.plain))
		cerr := w.Close()

		subject := fmt.Sprintf("io.Copy(NewWriter(..., %#v, padding.PKCS7), bytes.NewReader(%v))", mode, test.cipher)
		if err != nil {
			t.Errorf("%s error: %v", subject, err)
		}
		if cerr != nil {
			t.Errorf("%s Close() error: %v", subject, cerr)
		}
		if !bytes.Equal(cipher.Bytes(), test.cipher) {
			t.Errorf("%s data = %v; want %v", subject, cipher.Bytes(), test.cipher)
		}
	}
}

func TestWriter_OneByte(t *testing.T) {
	for _, test := range tests {
		if test.readErr != nil {
			continue
		}
		cipher := new(bytes.Buffer)
		mode := fakeBlockMode{size: test.blockSize, delta: 1}

		w := NewWriter(cipher, mode, padding.PKCS7)
		_, err := io.Copy(w, iotest.OneByteReader(bytes.NewReader(test.plain)))
		cerr := w.Close()

		subject := fmt.Sprintf("io.Copy(NewWriter(..., %#v, padding.PKCS7), iotest.OneByteReader(bytes.NewReader(%v)))", mode, test.cipher)
		if err != nil {
			t.Errorf("%s error: %v", subject, err)
		}
		if cerr != nil {
			t.Errorf("%s Close() error: %v", subject, cerr)
		}
		if !bytes.Equal(cipher.Bytes(), test.cipher) {
			t.Errorf("%s data = %v; want %v", subject, cipher.Bytes(), test.cipher)
		}
	}
}

func TestWriter_TightBuffer(t *testing.T) {
	for _, test := range tests {
		if test.readErr != nil {
			continue
		}
		cipher := new(bytes.Buffer)
		mode := fakeBlockMode{size: test.blockSize, delta: 1}

		w := newWriter(cipher, mode, padding.PKCS7, test.blockSize)
		_, err := io.Copy(w, bytes.NewReader(test.plain))
		cerr := w.Close()

		subject := fmt.Sprintf("io.Copy(newWriter(..., %#v, padding.PKCS7, %d), bytes.NewReader(%v)))", mode, test.blockSize, test.cipher)
		if err != nil {
			t.Errorf("%s error: %v", subject, err)
		}
		if cerr != nil {
			t.Errorf("%s Close() error: %v", subject, cerr)
		}
		if !bytes.Equal(cipher.Bytes(), test.cipher) {
			t.Errorf("%s data = %v; want %v", subject, cipher.Bytes(), test.cipher)
		}
	}
}

type fakeBlockMode struct {
	delta byte
	size  int
}

func (mode fakeBlockMode) BlockSize() int {
	return mode.size
}

func (mode fakeBlockMode) CryptBlocks(dst, src []byte) {
	for i := range src {
		dst[i] = src[i] + mode.delta
	}
}
