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

package uuids

import (
	"bytes"
	"strings"
	"testing"
)

var hexTests = []struct {
	u UUID
	s string
}{
	{
		UUID{},
		"00000000-0000-0000-0000-000000000000",
	},
	{
		UUID{0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b, 0xf6},
		"f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
	},
}

func TestParse(t *testing.T) {
	for _, test := range hexTests {
		u, err := Parse(test.s)
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", test.s, err)
		}
		if u != test.u {
			t.Errorf("Parse(%q) = %v; want %v", test.s, u, test.u)
		}
	}

	parseTests := []struct {
		s    string
		u    UUID
		fail bool
	}{
		{
			s: "f81d4fae7dec11d0a76500a0c91e6bf6",
			u: UUID{0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b, 0xf6},
		},
		{
			s:    "",
			fail: true,
		},
		{
			s:    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			fail: true,
		},
		{
			s:    "f81d4fae7dec11d0a76500a0c91e6bf",
			fail: true,
		},
		{
			s:    "f81d4fae7dec11d0a76500a0c91e6bf6ad",
			fail: true,
		},
		{
			s:    "f81d4fae7dec11d0a76500a0c91e6bf6a",
			fail: true,
		},
	}
	for _, test := range parseTests {
		u, err := Parse(test.s)
		if (err != nil) != test.fail {
			if test.fail {
				t.Errorf("Parse(%q) should return an error", test.s)
			} else {
				t.Errorf("Parse(%q) unexpected error: %v", test.s, err)
			}
		}
		if u != test.u {
			t.Errorf("Parse(%q) = %v; want %v", test.s, u, test.u)
		}
	}
}

func TestAppendHex(t *testing.T) {
	for _, test := range hexTests {
		{
			s := test.u.AppendHex(make([]byte, 0, 36))
			if !bytes.Equal(s, []byte(test.s)) {
				t.Errorf("UUID(%v).AppendHex(make([]byte, 0)) = %q; want %q", [16]byte(test.u), s, test.s)
			}
		}

		{
			s := test.u.AppendHex(make([]byte, 0, 36))
			if !bytes.Equal(s, []byte(test.s)) {
				t.Errorf("UUID(%v).AppendHex(make([]byte, 0, 36)) = %q; want %q", [16]byte(test.u), s, test.s)
			}
		}

		{
			b := make([]byte, 0, 39)
			b = append(b, "foo"...)
			s := test.u.AppendHex(b)
			if !bytes.Equal(s, []byte("foo"+test.s)) {
				t.Errorf("UUID(%v).AppendHex(\"foo\") = %q; want %q", [16]byte(test.u), s, "foo"+test.s)
			}
		}
	}
}

func TestString(t *testing.T) {
	for _, test := range hexTests {
		s := test.u.String()
		if s != test.s {
			t.Errorf("UUID(%v).String() = %q; want %q", [16]byte(test.u), s, test.s)
		}
	}
}

func TestNew3(t *testing.T) {
	tests := []struct {
		namespace UUID
		id        []byte
		u         UUID
	}{
		{
			DNS, []byte("www.example.com"),
			UUID{0x5d, 0xf4, 0x18, 0x81, 0x3a, 0xed, 0x35, 0x15, 0x88, 0xa7, 0x2f, 0x4a, 0x81, 0x4c, 0xf0, 0x9e},
		},
		{
			DNS, []byte("www.widgets.com"),
			UUID{0x3d, 0x81, 0x3c, 0xbb, 0x47, 0xfb, 0x32, 0xba, 0x91, 0xdf, 0x83, 0x1e, 0x15, 0x93, 0xac, 0x29},
		},
	}

	for _, test := range tests {
		u := New3(test.namespace, test.id)
		if u != test.u {
			t.Errorf("New3(%v, %q) = %v; want %v", test.namespace, test.id, u, test.u)
		}
	}
}

func TestNew4(t *testing.T) {
	const random = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\xe0\xe1"

	u, err := New4(strings.NewReader(random))
	if err != nil {
		t.Fatal("New4 error:", err)
	}

	if version := u[6] >> 4; version != 4 {
		t.Errorf("New4() = %v, version = %d; want 4", u, version)
	}
	if variant := u[8] >> 5; variant&6 != 4 {
		t.Errorf("New4() = %v, variant = %d; want 4", u, variant&6)
	}
}

func TestNew5(t *testing.T) {
	tests := []struct {
		namespace UUID
		id        []byte
		u         UUID
	}{
		{
			DNS, []byte("www.example.com"),
			UUID{0x2e, 0xd6, 0x65, 0x7d, 0xe9, 0x27, 0x56, 0x8b, 0x95, 0xe1, 0x26, 0x65, 0xa8, 0xae, 0xa6, 0xa2},
		},
	}

	for _, test := range tests {
		u := New5(test.namespace, test.id)
		if u != test.u {
			t.Errorf("New5(%v, %q) = %v; want %v", test.namespace, test.id, u, test.u)
		}
	}
}
