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

package kdbcrypt

import (
	"bytes"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestDecrypter(t *testing.T) {
	tests := []struct {
		db     string
		params Params
		hash   [32]byte
	}{
		{
			db: "passwordonly.kdb",
			params: Params{
				Key: Key{
					Password: []byte("swordfish"),
					MasterSeed: [16]byte{
						0xd4, 0x80, 0x93, 0xfd, 0x7a, 0xf7, 0x8c, 0x88,
						0xef, 0x20, 0x14, 0xc6, 0x7e, 0x67, 0xd1, 0xcb,
					},
					TransformSeed: [32]byte{
						0x13, 0x85, 0x9e, 0xdf, 0x26, 0x92, 0x5b, 0x40,
						0x26, 0xde, 0x42, 0xf2, 0x16, 0xee, 0xa5, 0x25,
						0xe5, 0xe4, 0xae, 0x4b, 0x8f, 0xf3, 0xe0, 0x51,
						0x3c, 0x3d, 0x74, 0xa6, 0x19, 0x0f, 0xec, 0xea,
					},
					TransformRounds: 50000,
				},
				Cipher: RijndaelCipher,
				IV: [16]byte{
					0x59, 0xb9, 0xa0, 0x2a, 0xbf, 0x60, 0x9c, 0x25,
					0x4a, 0xa7, 0xfb, 0x76, 0x71, 0x58, 0xba, 0x49,
				},
			},
			hash: [32]byte{
				0x91, 0xe8, 0x9e, 0x79, 0x2e, 0x51, 0xa4, 0x2e,
				0x19, 0xc6, 0xaf, 0x60, 0x09, 0x23, 0xe0, 0x27,
				0xa1, 0x03, 0x1a, 0x76, 0x1a, 0x6f, 0x13, 0x51,
				0x7a, 0x5f, 0x64, 0xa3, 0x9c, 0x34, 0x4a, 0x44,
			},
		},
	}

	for _, test := range tests {
		db := testFile(test.db)
		io.CopyN(ioutil.Discard, db, 124)
		d, err := NewDecrypter(db, &test.params)
		if err != nil {
			t.Errorf("NewDecrypter(testFile(%q), %+v) error: %v", test.db, test.params, err)
			continue
		}
		s := sha256.New()

		_, err = io.Copy(s, d)

		if err != nil {
			t.Errorf("NewDecrypter(testFile(%q), %+v) read error: %v", test.db, test.params, err)
			continue
		}
		if hash := s.Sum(nil); !bytes.Equal(hash, test.hash[:]) {
			t.Errorf("NewDecrypter(testFile(%q), %+v) corrupted output", test.db, test.params)
		}
	}
}

func testFile(name string) *bytes.Buffer {
	p := filepath.Join("testdata", name)
	f, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		panic(err)
	}
	return buf
}
