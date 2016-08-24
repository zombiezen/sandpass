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

package padding

import (
	"bytes"
	"testing"
)

type padtest struct {
	unpadded  []byte
	padded    []byte
	blockSize int
	err       error
}

var pkcs7tests = []padtest{
	{
		unpadded:  []byte{},
		padded:    []byte{0x03, 0x03, 0x03},
		blockSize: 3,
	},
	{
		unpadded:  []byte{0x41},
		padded:    []byte{0x41, 0x02, 0x02},
		blockSize: 3,
	},
	{
		unpadded:  []byte{0x41, 0x64},
		padded:    []byte{0x41, 0x64, 0x01},
		blockSize: 3,
	},
	{
		unpadded:  []byte{0x41, 0x64, 0x2a},
		padded:    []byte{0x41, 0x64, 0x2a, 0x03, 0x03, 0x03},
		blockSize: 3,
	},
	{
		unpadded:  []byte{0x41, 0x64, 0x2a, 0x77},
		padded:    []byte{0x41, 0x64, 0x2a, 0x77, 0x02, 0x02},
		blockSize: 3,
	},
	{
		unpadded:  []byte{0x41, 0x64, 0x2a, 0x77, 0xee},
		padded:    []byte{0x41, 0x64, 0x2a, 0x77, 0xee, 0x01},
		blockSize: 3,
	},
	{
		padded:    []byte{},
		unpadded:  []byte{},
		blockSize: 0,
		err:       ErrBadBlockSize,
	},
	{
		padded:    []byte{0x01},
		unpadded:  []byte{0x01},
		blockSize: 1,
		err:       ErrBadBlockSize,
	},
	{
		padded:    pkcs7padding(255),
		unpadded:  []byte{},
		blockSize: 255,
	},
	{
		padded:    make([]byte, 256),
		unpadded:  make([]byte, 256),
		blockSize: 256,
		err:       ErrBadBlockSize,
	},
	{
		padded:    []byte{0x41, 0x03, 0x03},
		unpadded:  []byte{0x41, 0x03, 0x03},
		blockSize: 3,
		err:       ErrWrongPadding,
	},
	{
		padded:    []byte{0x41, 0x02, 0x00},
		unpadded:  []byte{0x41, 0x02, 0x00},
		blockSize: 3,
		err:       ErrWrongPadding,
	},
	{
		padded:    []byte{0x04, 0x04, 0x04},
		unpadded:  []byte{0x04, 0x04, 0x04},
		blockSize: 3,
		err:       ErrWrongPadding,
	},
	{
		padded:    []byte{0x02, 0x02},
		unpadded:  []byte{0x02, 0x02},
		blockSize: 3,
		err:       ErrDataSize,
	},
	{
		padded:    []byte{0x00, 0x00, 0x04, 0x04, 0x04, 0x04},
		unpadded:  []byte{0x00, 0x00, 0x04, 0x04, 0x04, 0x04},
		blockSize: 3,
		err:       ErrWrongPadding,
	},
}

func TestPKCS7_Pad(t *testing.T) {
	for _, test := range pkcs7tests {
		if test.err != nil {
			// Error tests are for unpadding.
			continue
		}

		{
			b := make([]byte, len(test.unpadded))
			copy(b, test.unpadded)
			out := PKCS7.Pad(b, test.blockSize)
			if !bytes.Equal(out, test.padded) {
				t.Errorf("PKCS7(%v) with fitted buffer = %v; want %v", test.unpadded, out, test.padded)
			}
		}

		{
			b := make([]byte, len(test.unpadded), len(test.padded))
			copy(b, test.unpadded)
			out := PKCS7.Pad(b, test.blockSize)
			if !bytes.Equal(out, test.padded) {
				t.Errorf("PKCS7(%v) with extended buffer = %v; want %v", test.unpadded, out, test.padded)
			}
		}
	}
}

func TestPKCS7_Strip(t *testing.T) {
	for _, test := range pkcs7tests {
		b := make([]byte, len(test.padded))
		copy(b, test.padded)
		out, err := PKCS7.Strip(b, test.blockSize)
		if err != test.err {
			t.Errorf("StripPKCS7(%v, %d) error = %v; want %v", test.padded, test.blockSize, err, test.err)
		}
		if !bytes.Equal(out, test.unpadded) {
			t.Errorf("StripPKCS7(%v, %d) = %v; want %v", test.padded, test.blockSize, out, test.unpadded)
		}
	}
}

func pkcs7padding(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(n)
	}
	return p
}
