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
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"zombiezen.com/go/sandpass/pkg/fakerand"
	"zombiezen.com/go/sandpass/pkg/kdbcrypt"
)

// sanitizeOptions returns a copy of opts that has defaults suitable for testing.
func sanitizeOptions(opts *Options) *Options {
	o := new(Options)
	if opts != nil {
		*o = *opts
	}
	if o.Rand == nil {
		o.Rand = fakerand.New()
	}
	return o
}

func TestNew(t *testing.T) {
	db, err := New(sanitizeOptions(&Options{
		Password: "swordfish",
	}))
	if err != nil {
		t.Fatal("New:", err)
	}

	if n := db.Root().NGroups(); n > 0 {
		t.Errorf("db.Root().NGroups() = %d; want 0", n)
	}
	if n := db.Root().NEntries(); n > 0 {
		t.Errorf("db.Root().NEntries() = %d; want 0", n)
	}
}

func TestNewEntry_DifferentIDs(t *testing.T) {
	db, err := New(sanitizeOptions(nil))
	if err != nil {
		t.Fatal("New:", err)
	}
	g := db.Root().NewSubgroup()

	e1, err := g.NewEntry()
	if err != nil {
		t.Fatal("g.NewEntry() #1:", err)
	}
	e2, err := g.NewEntry()
	if err != nil {
		t.Fatal("g.NewEntry() #2:", err)
	}

	if e1.UUID == e2.UUID {
		t.Errorf("g.NewEntry().UUID == g.NewEntry().UUID (%v); want different", e1.UUID)
	}
}

func TestNewSubgroup_DifferentIDs(t *testing.T) {
	db, err := New(sanitizeOptions(nil))
	if err != nil {
		t.Fatal("New:", err)
	}

	g1 := db.Root().NewSubgroup()
	g2 := db.Root().NewSubgroup()

	if g1.ID == g2.ID {
		t.Errorf("db.Root().NewSubgroup().ID == db.Root().NewSubgroup().ID (%x); want different", g1.ID)
	}
}

func TestEntitySetParent(t *testing.T) {
	const (
		rootGroup = iota + 1
		groupA
		groupB
	)
	tests := []struct {
		name string
		src  int
		dst  int
		err  bool
	}{
		{name: "move A to B", src: groupA, dst: groupB},
		{name: "move B to A", src: groupB, dst: groupA},
		{name: "move A to root fails", src: groupA, dst: rootGroup, err: true},
		{name: "move A to A", src: groupA, dst: groupA},
	}
	for _, test := range tests {
		db, err := New(sanitizeOptions(nil))
		if err != nil {
			t.Errorf("%s: New: %v", test.name, err)
			continue
		}
		a := db.Root().NewSubgroup()
		a.Name = "Group A"
		b := db.Root().NewSubgroup()
		b.Name = "Group B"
		groups := [...]*Group{
			rootGroup: db.Root(),
			groupA:    a,
			groupB:    b,
		}
		groupString := func(g *Group) string {
			switch g {
			case nil:
				return "<nil>"
			case groups[rootGroup]:
				return "root"
			case groups[groupA]:
				return "Group A"
			case groups[groupB]:
				return "Group B"
			default:
				return "<unknown>"
			}
		}
		ent, err := groups[test.src].NewEntry()
		if err != nil {
			t.Errorf("%s: NewEntry: %v", test.name, err)
			continue
		}

		err = ent.SetParent(groups[test.dst])
		if err != nil && !test.err {
			t.Errorf("%s: SetParent returned error: %v", test.name, err)
		} else if err == nil && test.err {
			t.Errorf("%s: SetParent did not return an error", test.name)
		}
		if err != nil || test.src == test.dst {
			// Entry should not have moved.
			if !hasEntry(groups[test.src], ent) {
				t.Errorf("%s: entry is missing from original parent", test.name)
			}
			if test.src != test.dst && hasEntry(groups[test.dst], ent) {
				t.Errorf("%s: entry is present in new parent", test.name)
			}
			if p := ent.Parent(); p != groups[test.src] {
				t.Errorf("%s: entry parent = %s; want %s", test.name, groupString(p), groupString(groups[test.src]))
			}
		} else {
			// Entry should have moved.
			if hasEntry(groups[test.src], ent) {
				t.Errorf("%s: entry is present in original parent", test.name)
			}
			if !hasEntry(groups[test.dst], ent) {
				t.Errorf("%s: entry is missing from new parent", test.name)
			}
			if p := ent.Parent(); p != groups[test.dst] {
				t.Errorf("%s: entry parent = %s; want %s", test.name, groupString(p), groupString(groups[test.dst]))
			}
		}
	}
}

func hasEntry(g *Group, e *Entry) bool {
	for i := 0; i < g.NEntries(); i++ {
		if g.Entry(i) == e {
			return true
		}
	}
	return false
}

func TestGroupSetParent(t *testing.T) {
	const (
		rootGroup = iota + 1
		groupA
		groupAA
		groupAAA
		groupB
	)
	srcs := [...]int{
		groupA:   rootGroup,
		groupAA:  groupA,
		groupAAA: groupAA,
		groupB:   rootGroup,
	}

	tests := []struct {
		name string
		grp  int
		dst  int
		err  bool
	}{
		{name: "move A under B", grp: groupA, dst: groupB},
		{name: "move root under root", grp: rootGroup, dst: rootGroup, err: true},
		{name: "move root under A", grp: rootGroup, dst: groupA, err: true},
		{name: "move A under root (no-op)", grp: groupA, dst: rootGroup},
		{name: "move A under A", grp: groupA, dst: groupA, err: true},
		{name: "move A under AA", grp: groupA, dst: groupAA, err: true},
		{name: "move A under AAA", grp: groupA, dst: groupAAA, err: true},
		{name: "move AA under root", grp: groupAA, dst: rootGroup},
	}
	for _, test := range tests {
		db, err := New(sanitizeOptions(nil))
		if err != nil {
			t.Errorf("%s: New: %v", test.name, err)
			continue
		}
		a := db.Root().NewSubgroup()
		a.Name = "Group A"
		aa := a.NewSubgroup()
		aa.Name = "Group AA"
		aaa := aa.NewSubgroup()
		aaa.Name = "Group AAA"
		b := db.Root().NewSubgroup()
		b.Name = "Group B"
		groups := [...]*Group{
			rootGroup: db.Root(),
			groupA:    a,
			groupAA:   aa,
			groupAAA:  aaa,
			groupB:    b,
		}
		groupString := func(g *Group) string {
			switch g {
			case nil:
				return "<nil>"
			case groups[rootGroup]:
				return "root"
			case groups[groupA]:
				return "Group A"
			case groups[groupAA]:
				return "Group AA"
			case groups[groupAAA]:
				return "Group AAA"
			case groups[groupB]:
				return "Group B"
			default:
				return "<unknown>"
			}
		}

		g, src := groups[test.grp], srcs[test.grp]
		err = g.SetParent(groups[test.dst])
		if err != nil && !test.err {
			t.Errorf("%s: SetParent returned error: %v", test.name, err)
		} else if err == nil && test.err {
			t.Errorf("%s: SetParent did not return an error", test.name)
		}
		if err != nil || src == test.dst {
			// Entry should not have moved.
			if src != 0 && !hasSubgroup(groups[src], g) {
				t.Errorf("%s: group is missing from original parent", test.name)
			}
			if src != test.dst && hasSubgroup(groups[test.dst], g) {
				t.Errorf("%s: group is present in new parent", test.name)
			}
			if p := g.Parent(); p != groups[src] {
				t.Errorf("%s: group parent = %s; want %s", test.name, groupString(p), groupString(groups[src]))
			}
		} else {
			// Entry should have moved.
			if src != 0 && hasSubgroup(groups[src], g) {
				t.Errorf("%s: group is present in original parent", test.name)
			}
			if !hasSubgroup(groups[test.dst], g) {
				t.Errorf("%s: group is missing from new parent", test.name)
			}
			if p := g.Parent(); p != groups[test.dst] {
				t.Errorf("%s: group parent = %s; want %s", test.name, groupString(p), groupString(groups[test.dst]))
			}
		}
	}
}

func hasSubgroup(g, sub *Group) bool {
	for i := 0; i < g.NGroups(); i++ {
		if g.Group(i) == sub {
			return true
		}
	}
	return false
}

func TestOpenDecrypt(t *testing.T) {
	tests := []struct {
		openParams
		err error
	}{
		{
			openParams: openParams{
				db:   "passwordonly.kdb",
				opts: &Options{Password: "swordfish"},
			},
			err: nil,
		},
		{
			openParams: openParams{
				db: "passwordonly.kdb",
				opts: &Options{
					ComputedKey: (&kdbcrypt.Key{
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
					}).Compute(),
				},
			},
			err: nil,
		},
		{
			openParams: openParams{
				db:   "passwordonly.kdb",
				opts: &Options{Password: "123457"},
			},
			err: ErrHashMismatch,
		},
		{
			openParams: openParams{
				db:   "passwordonly.kdb",
				opts: &Options{Password: "123457"},
			},
			err: ErrHashMismatch,
		},
		{
			openParams: openParams{
				db:      "keyfileonly.kdb",
				keyfile: "test.key",
			},
			err: nil,
		},
		{
			openParams: openParams{
				db:      "passwordandkey.kdb",
				keyfile: "test.key",
				opts: &Options{
					Password: "swordfish",
				},
			},
			err: nil,
		},
	}

	for _, test := range tests {
		_, err := test.open()

		if err != test.err {
			t.Errorf("%v error: %v; want %v", test.openParams, err, test.err)
		}
	}
}

func TestWrite_New(t *testing.T) {
	opts := &Options{
		Password: "swordfish",
	}
	db, err := New(sanitizeOptions(opts))
	if err != nil {
		t.Fatal("New:", err)
	}
	buf := new(bytes.Buffer)

	err = db.Write(buf)

	if err != nil {
		t.Fatal("Write:", err)
	}
	rdb, err := Open(buf, opts)
	if err != nil {
		t.Fatal("Open:", err)
	}
	if n := rdb.Root().NGroups(); n > 0 {
		t.Errorf("rdb.Root().NGroups() = %d; want 0", n)
	}
	if n := rdb.Root().NEntries(); n > 0 {
		t.Errorf("rdb.Root().NEntries() = %d; want 0", n)
	}
}

func TestWrite_GroupAndEntry(t *testing.T) {
	opts := &Options{
		Password: "swordfish",
	}
	db, err := New(sanitizeOptions(opts))
	if err != nil {
		t.Fatal("New:", err)
	}
	buf := new(bytes.Buffer)

	{
		g := db.Root().NewSubgroup()
		g.Name = "My Group"
		e, err := g.NewEntry()
		if err != nil {
			t.Fatal("NewEntry:", err)
		}
		e.Title = "My User"
	}
	err = db.Write(buf)

	if err != nil {
		t.Fatal("Write:", err)
	}
	rdb, err := Open(buf, opts)
	if err != nil {
		t.Fatal("Open:", err)
	}
	if n := rdb.Root().NEntries(); n > 0 {
		t.Errorf("rdb.Root().NEntries() = %d; want 0", n)
	}
	if n := rdb.Root().NGroups(); n != 1 {
		t.Fatalf("rdb.Root().NGroups() = %d; want 1", n)
	}
	g := rdb.Root().Group(0)
	if g.Name != "My Group" {
		t.Errorf("rdb.Root().Group(0).Name = %q; want %q", g.Name, "My Group")
	}
	if n := g.NEntries(); n != 1 {
		t.Fatalf("rdb.Root().Groups(0).NEntries() = %d; want 1", n)
	}
	e := g.Entry(0)
	if e.Title != "My User" {
		t.Errorf("rdb.Root().Groups(0).Entry(0).Title = %q; want %q", g.Name, "My User")
	}
}

func TestWrite_Identity(t *testing.T) {
	tests := []struct {
		openParams
		cryptTextDiffers bool // used for verifying IV changes
	}{
		{
			openParams: openParams{
				db: "passwordonly.kdb",
				opts: &Options{
					Password:           "swordfish",
					StaticIVForTesting: true,
				},
			},
		},
		{
			openParams: openParams{
				db: "passwordonly.kdb",
				opts: &Options{
					ComputedKey: (&kdbcrypt.Key{
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
					}).Compute(),
					StaticIVForTesting: true,
				},
			},
		},
		{
			openParams: openParams{
				db: "files.kdb",
				opts: &Options{
					Password:           "swordfish",
					StaticIVForTesting: true,
				},
			},
		},
		{
			openParams: openParams{
				db: "passwordonly.kdb",
				opts: &Options{
					Password:           "swordfish",
					StaticIVForTesting: false,
				},
			},
			cryptTextDiffers: true,
		},
	}

	for _, test := range tests {
		want, err := testFile(test.db)
		if err != nil {
			t.Errorf("testFile(%q) error: %v", test.db, err)
			continue
		}
		wantPlain, err := debugDecrypt(want.Bytes(), test.opts)
		if err != nil {
			t.Errorf("debugDecrypt(testFile(%q), %v) error: %v", test.db, test.opts, err)
			continue
		}
		db, err := test.open()
		if err != nil {
			t.Errorf("%v error: %v", test.openParams, err)
			continue
		}

		out := new(bytes.Buffer)
		err = db.Write(out)

		if err != nil {
			t.Errorf("%v.Write(w) error: %v", test.openParams, err)
			continue
		}
		outPlain, err := debugDecrypt(out.Bytes(), test.opts)
		if err != nil {
			t.Errorf("could not decrypt output of %v.Write(w): %v\n%s\n; want\n%s", test.openParams, err, hex.Dump(out.Bytes()), hex.Dump(want.Bytes()))
			continue
		}
		if !bytes.Equal(outPlain, wantPlain) {
			t.Errorf("%v.Write(w) header:\n%s\nplain:\n%s\n; want header:\n%s\nplain:\n%s",
				test.openParams,
				hex.Dump(out.Bytes()[:headerSize]), hex.Dump(outPlain),
				hex.Dump(want.Bytes()[:headerSize]), hex.Dump(wantPlain))
		}
		if test.cryptTextDiffers && bytes.Equal(out.Bytes()[headerSize:], want.Bytes()[headerSize:]) {
			t.Errorf("%v.Write(w) has identical cipher text; should differ", test.openParams)
		} else if !test.cryptTextDiffers && !bytes.Equal(out.Bytes(), want.Bytes()) {
			t.Errorf("%v.Write(w) header:\n%s\nplain:\n%s\n; want header:\n%s\nplain:\n%s",
				test.openParams,
				hex.Dump(out.Bytes()[:headerSize]), hex.Dump(outPlain),
				hex.Dump(want.Bytes()[:headerSize]), hex.Dump(wantPlain))
		}
	}
}

func testFile(name string) (*bytes.Buffer, error) {
	p := filepath.Join("testdata", name)
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return nil, err
	}
	return buf, nil
}

func debugDecrypt(data []byte, opts *Options) ([]byte, error) {
	r := bytes.NewReader(data[:headerSize])
	h := new(header)
	if err := h.read(r); err != nil {
		return nil, err
	}
	p := new(kdbcrypt.Params)
	var err error
	if opts != nil && opts.ComputedKey != nil {
		err = h.initComputedCryptParams(p, opts.ComputedKey)
	} else {
		// TODO(light): keyfile
		err = h.initCryptParams(p, []byte(opts.getPassword()), nil)
	}
	if err != nil {
		return nil, err
	}
	return decryptDatabase(data[headerSize:], p, h.contentHash[:])
}

type openParams struct {
	db      string
	keyfile string
	opts    *Options
}

func (p openParams) open() (*Database, error) {
	opts := sanitizeOptions(p.opts)
	if p.keyfile != "" {
		kf, err := testFile(p.keyfile)
		if err != nil {
			return nil, err
		}
		opts.KeyFile = kf
	}
	f, err := testFile(p.db)
	if err != nil {
		return nil, err
	}
	return Open(f, opts)
}

func (p openParams) String() string {
	return fmt.Sprintf("Open(open(%q), %+v)", p.db, p.opts)
}
