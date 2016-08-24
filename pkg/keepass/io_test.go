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
	"bytes"
	"testing"
	"time"
)

var dateTests = []struct {
	t time.Time
	b []byte
}{
	{
		time.Time{},
		[]byte{0x2e, 0xdf, 0x39, 0x7e, 0xfb},
	},
	{
		time.Date(2015, time.February, 19, 2, 32, 15, 0, time.UTC),
		[]byte{0x1f, 0x7c, 0xa6, 0x28, 0x0f},
	},
	{
		time.Date(2015, time.February, 18, 18, 32, 15, 0, time.FixedZone("PST", -8*60*60)),
		[]byte{0x1f, 0x7c, 0xa6, 0x28, 0x0f},
	},
}

func TestReadDate(t *testing.T) {
	for _, test := range dateTests {
		b := make([]byte, 5)
		copy(b, test.b)
		ti, err := readDate("test field", b)
		if err != nil {
			t.Errorf("readDate(%v) error: %v", test.b, err)
		}
		if !ti.Equal(test.t) {
			t.Errorf("readDate(%v) = %v; want %v", test.b, ti, test.t)
		}
	}
}

func TestWriteDateField(t *testing.T) {
	head := []byte{0x34, 0x12, 0x05, 0x00, 0x00, 0x00}
	for _, test := range dateTests {
		var buf bytes.Buffer
		writeDateField(&writer{w: &buf}, 0x1234, test.t)
		b := buf.Bytes()
		if !bytes.HasPrefix(b, head) {
			t.Errorf("writeDateField(w, 0x1234, %v) = %v; want prefix %v", test.t, b, head)
		}
		if len(b) >= len(head) {
			b = b[len(head):]
			if !bytes.Equal(b, test.b) {
				t.Errorf("writeDateField(w, 0x1234, %v)[%d:] = %v; want %v", test.t, len(head), b, test.b)
			}
		}
	}
}
