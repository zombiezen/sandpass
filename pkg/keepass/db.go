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

// Package keepass reads and writes the KeePass1 database format.
package keepass // import "zombiezen.com/go/sandpass/pkg/keepass"

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"zombiezen.com/go/sandpass/pkg/kdbcrypt"
	"zombiezen.com/go/sandpass/pkg/uuids"
)

// A Database represents a decrypted KDB file.
type Database struct {
	cparams  kdbcrypt.Params
	staticIV bool
	root     *Group
	groups   map[uint32]*Group
	entries  []*Entry
	meta     []*Entry
	rand     io.Reader
}

// init is called after cparams is filled in to initialize the database.
func (db *Database) init(g []Group, e []Entry, opts *Options) {
	// Clear inputted key material.
	if db.cparams.ComputedKey == nil {
		panic("key should have been precomputed")
	}
	db.cparams.Key.Password, db.cparams.Key.KeyFileHash = nil, nil

	db.staticIV = opts.staticIV()
	db.groups = make(map[uint32]*Group, len(g))
	db.entries = make([]*Entry, 0, len(e))
	db.rand = opts.getRand()
	db.root = &Group{Name: "Root", db: db}
	for i := range g {
		gg := &g[i]
		db.groups[gg.ID] = gg
	}
	for i := range e {
		ee := &e[i]
		if ee.isMetaStream() {
			db.meta = append(db.meta, ee)
		} else {
			db.entries = append(db.entries, ee)
		}
	}
}

// New creates a new empty database.
func New(opts *Options) (*Database, error) {
	db := new(Database)
	if err := opts.initCryptParams(&db.cparams); err != nil {
		return nil, err
	}
	db.init(nil, nil, opts)
	return db, nil
}

// Root returns the root group.
func (db *Database) Root() *Group {
	return db.root
}

// Find returns the entry that matches the UUID or nil if not found.
func (db *Database) Find(uuid [16]byte) *Entry {
	for _, e := range db.entries {
		if e.UUID == uuid {
			return e
		}
	}
	return nil
}

// FindGroup returns the group that matches the group or nil if not found.
func (db *Database) FindGroup(id uint32) *Group {
	return db.groups[id]
}

// ComputedKey returns the computed encryption key of the database.
func (db *Database) ComputedKey() kdbcrypt.ComputedKey {
	return db.cparams.ComputedKey
}

// Entries returns a list of all entries in the database.
func (db *Database) Entries() []*Entry {
	e := make([]*Entry, len(db.entries))
	copy(e, db.entries)
	return e
}

// Write encodes the database to a writer.
func (db *Database) Write(w io.Writer) error {
	if !db.staticIV {
		_, err := io.ReadFull(db.rand, db.cparams.IV[:])
		if err != nil {
			return err
		}
	}
	buf := new(bytes.Buffer)
	enc, err := kdbcrypt.NewEncrypter(buf, &db.cparams)
	if err != nil {
		return err
	}
	ch := sha256.New()
	ngroups, nentries, err := db.writePlaintext(io.MultiWriter(enc, ch))
	if err != nil {
		return err
	}
	err = enc.Close()
	if err != nil {
		return err
	}

	h := header{
		// TODO(light): what does bit 1 do?
		encryptionFlags: makeEncryptionFlags(&db.cparams) | 1,
		masterSeed:      db.cparams.Key.MasterSeed,
		encryptionIV:    db.cparams.IV,
		numGroups:       uint32(ngroups),
		numEntries:      uint32(nentries),
		transformSeed:   db.cparams.Key.TransformSeed,
		transformRounds: db.cparams.Key.TransformRounds,
	}
	ch.Sum(h.contentHash[:0])

	if err := h.write(w); err != nil {
		return err
	}
	_, err = io.Copy(w, buf)
	return err
}

func (db *Database) writePlaintext(w io.Writer) (ngroups, nentries int, err error) {
	type frame struct {
		group *Group
		level int
	}
	type groupedEntry struct {
		*Entry
		gid uint32
	}

	stk := make([]frame, 0, 128)
	for i := len(db.root.groups) - 1; i >= 0; i-- {
		stk = append(stk, frame{group: db.root.groups[i], level: 0})
	}
	entries := make([]groupedEntry, 0, len(db.entries))
	for len(stk) > 0 {
		f := stk[len(stk)-1]
		stk = stk[:len(stk)-1]
		if err := f.group.write(w, f.level); err != nil {
			return ngroups, 0, err
		}
		ngroups++
		for _, e := range f.group.entries {
			entries = append(entries, groupedEntry{e, f.group.ID})
		}
		for i := len(f.group.groups) - 1; i >= 0; i-- {
			stk = append(stk, frame{group: f.group.groups[i], level: f.level + 1})
		}
	}
	for i, e := range entries {
		if err := e.write(w, e.gid); err != nil {
			return ngroups, i, err
		}
	}
	var metaID uint32
	if len(db.root.groups) > 0 {
		metaID = db.root.groups[0].ID
	}
	for i, m := range db.meta {
		if err := m.write(w, metaID); err != nil {
			return ngroups, len(entries) + i, err
		}
	}
	return ngroups, len(entries) + len(db.meta), nil
}

func (db *Database) nextGroupID() uint32 {
	if len(db.groups) >= 0x7fffffff {
		panic("keepass: too many groups")
	}
	for i := uint32(0); ; i++ {
		if db.groups[i] == nil {
			return i
		}
	}
}

// A Group is a hierarchial collection of entries.
type Group struct {
	ID   uint32
	Name string
	Icon Icon
	TimeInfo

	db      *Database
	groups  []*Group
	entries []*Entry
}

// Parent returns the containing group or nil if the group is the
// database's root.
func (g *Group) Parent() *Group {
	if g == g.db.root {
		return nil
	}
	if g.db.root.indexGroup(g) != -1 {
		return g.db.root
	}
	for _, gg := range g.db.groups {
		if gg.indexGroup(g) != -1 {
			return gg
		}
	}
	panic("group without parent")
}

// IsRoot reports whether the group is the database's root group.
func (g *Group) IsRoot() bool {
	return g == g.db.root
}

// Groups returns the groups as a slice.
func (g *Group) Groups() []*Group {
	gg := make([]*Group, len(g.groups))
	copy(gg, g.groups)
	return gg
}

// NGroups returns the number of subgroups this group has.
func (g *Group) NGroups() int {
	return len(g.groups)
}

// Group returns the group at index i.  If i is out of range,
// this method will panic.
func (g *Group) Group(i int) *Group {
	return g.groups[i]
}

// NewSubgroup creates a group inside g and returns it.
func (g *Group) NewSubgroup() *Group {
	id := g.db.nextGroupID()
	sub := &Group{ID: id, db: g.db}
	g.groups = append(g.groups, sub)
	g.db.groups[id] = sub
	return sub
}

// RemoveSubgroup removes sub from the group's children.
func (g *Group) RemoveSubgroup(sub *Group) error {
	if len(sub.entries) != 0 || len(sub.groups) != 0 {
		return fmt.Errorf("keepass: removing group %s (id=%d): not empty", sub.Name, sub.ID)
	}
	i := g.indexGroup(sub)
	if i == -1 {
		return fmt.Errorf("keepass: removing group %s (id=%d): not in group %s (id=%d)", sub.Name, sub.ID, g.Name, g.ID)
	}
	copy(g.groups[i:], g.groups[i+1:])
	g.groups[len(g.groups)-1] = nil
	g.groups = g.groups[:len(g.groups)-1]
	sub.db = nil
	return nil
}

func (g *Group) indexGroup(sub *Group) int {
	for i := range g.groups {
		if g.groups[i] == sub {
			return i
		}
	}
	return -1
}

// Entries returns the entries in the group as a slice.
func (g *Group) Entries() []*Entry {
	e := make([]*Entry, len(g.entries))
	copy(e, g.entries)
	return e
}

// NEntries returns the number of entries this group has.
func (g *Group) NEntries() int {
	return len(g.entries)
}

// Entry returns the entry at index i.  If i is out of range,
// this method will panic.
func (g *Group) Entry(i int) *Entry {
	return g.entries[i]
}

// NewEntry creates a new entry inside the group and returns it.
// An error is returned if the ID generation fails.
func (g *Group) NewEntry() (*Entry, error) {
	id, err := uuids.New4(g.db.rand)
	if err != nil {
		return nil, err
	}
	e := &Entry{UUID: id, db: g.db}
	g.entries = append(g.entries, e)
	g.db.entries = append(g.db.entries, e)
	return e, nil
}

// RemoveEntry removes e from the group's entries.
func (g *Group) RemoveEntry(e *Entry) error {
	var ok bool
	g.entries, ok = removeEntry(g.entries, e)
	if !ok {
		return fmt.Errorf("keepass: removing entry %s (id=%v): not in group %s (id=%d)", e.Title, e.UUID, g.Name, g.ID)
	}
	g.db.entries, _ = removeEntry(g.db.entries, e)
	e.db = nil
	return nil
}

func removeEntry(entries []*Entry, e *Entry) ([]*Entry, bool) {
	i, n := 0, len(entries)
	for ; i < n; i++ {
		if entries[i] == e {
			break
		}
	}
	if i >= n {
		return entries, false
	}
	copy(entries[i:], entries[i+1:])
	entries[n-1] = nil
	return entries[:n-1], true
}

// An Entry stores a username and password.
type Entry struct {
	UUID     uuids.UUID
	Title    string
	Icon     Icon
	URL      string
	Username string
	Password string
	Notes    string
	TimeInfo
	Attachment struct {
		Name string
		Data []byte
	}

	db *Database
}

// Parent returns the entry's group.
func (e *Entry) Parent() *Group {
	for _, g := range e.db.groups {
		for _, ee := range g.entries {
			if ee == e {
				return g
			}
		}
	}
	panic("entry without parent")
}

// SetParent moves the entry to another group.
func (e *Entry) SetParent(parent *Group) error {
	for _, ee := range parent.entries {
		if ee == e {
			// Already the parent.
			return nil
		}
	}
	if parent.IsRoot() {
		return fmt.Errorf("keepass: cannot set parent of entry %q (id=%v) to root", e.Title, e.UUID)
	}
	old := e.Parent()
	old.entries, _ = removeEntry(old.entries, e)
	parent.entries = append(parent.entries, e)
	return nil
}

func (e *Entry) isMetaStream() bool {
	return e.Title == "Meta-Info" && e.Username == "SYSTEM" && e.URL == "$" && e.Icon == 0 && e.Notes != "" && e.Attachment.Name == "bin-stream"
}

// HasAttachment reports whether an entry has a file attachment.
func (e *Entry) HasAttachment() bool {
	return e.Attachment.Name != ""
}

type Icon uint32

// TimeInfo holds all of the temporal data for a group or entry.
type TimeInfo struct {
	LastModificationTime time.Time
	CreationTime         time.Time
	LastAccessTime       time.Time
	ExpiryTime           time.Time
}

// Expires reports whether the item has an expiry.
func (ti *TimeInfo) Expires() bool {
	return !ti.ExpiryTime.IsZero()
}

// Open decrypts and reads a database.
func Open(r io.Reader, opts *Options) (*Database, error) {
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, headerSize); err != nil {
		return nil, err
	}
	var h header
	if err := h.read(&buf); err != nil {
		return nil, err
	}
	// TODO(light): put a limit on this read
	crypt, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	kh, err := opts.getKeyFileHash()
	if err != nil {
		return nil, err
	}

	// TODO(light): try non-UTF8 encodings
	db := new(Database)
	if opts != nil && opts.ComputedKey != nil {
		err = h.initComputedCryptParams(&db.cparams, opts.ComputedKey)
	} else {
		err = h.initCryptParams(&db.cparams, []byte(opts.getPassword()), kh)
	}
	if err != nil {
		return nil, err
	}
	plain, err := decryptDatabase(crypt, &db.cparams, h.contentHash[:])
	if err != nil {
		return nil, err
	}

	return parse(db, bytes.NewReader(plain), int(h.numGroups), int(h.numEntries), opts)
}

type parseState struct {
	groups        map[uint32]*Group
	groupLevels   map[*Group]uint16
	entryGroupIDs map[*Entry]uint32
}

func parse(db *Database, r io.Reader, numGroups, numEntries int, opts *Options) (*Database, error) {
	state := parseState{
		groups:        make(map[uint32]*Group),
		groupLevels:   make(map[*Group]uint16),
		entryGroupIDs: make(map[*Entry]uint32),
	}
	groups := make([]Group, numGroups)
	for i := range groups {
		groups[i].db = db
		err := groups[i].read(&state, r)
		if err != nil {
			return nil, err
		}
	}
	entries := make([]Entry, numEntries)
	for i := range entries {
		entries[i].db = db
		err := entries[i].read(&state, r)
		if err != nil {
			return nil, err
		}
	}
	db.init(groups, entries, opts)

	for i := range groups {
		g := &groups[i]
		parent := state.findGroupParent(db, groups, i)
		if parent == nil {
			return nil, errGroupsInconsistent
		}
		parent.groups = append(parent.groups, g)
	}
	for i := range entries {
		e := &entries[i]
		if e.isMetaStream() {
			// TODO(light): parse meta stream
			continue
		}
		eg := state.entryGroupIDs[e]
		if g := state.groups[eg]; g != nil {
			g.entries = append(g.entries, e)
		} else {
			// TODO(light): log warning
			db.root.entries = append(db.root.entries, e)
		}
	}

	return db, nil
}

func (state *parseState) findGroupParent(db *Database, groups []Group, i int) *Group {
	g := &groups[i]
	level := state.groupLevels[g]
	if level == 0 {
		return db.root
	}
	for j := i - 1; j >= 0; j-- {
		gj := &groups[j]
		if delta := int16(state.groupLevels[gj] - level); delta == -1 {
			return gj
		} else if delta < 0 {
			return nil
		}
	}
	return nil
}

func (g *Group) read(state *parseState, r io.Reader) error {
	fr := newFieldReader(r)
	var ferr error
	groupIDSet, groupLevelSet := false, false
	for {
		k, v, err := fr.next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		} else if ferr != nil {
			continue
		}
		ferr = g.readField(state, k, v)
		if ferr == nil {
			switch k {
			case groupIDField:
				groupIDSet = true
			case groupLevelField:
				groupLevelSet = true
			}
		}
	}
	if !groupIDSet || !groupLevelSet {
		return errors.New("keepass: missing group ID or level")
	}
	return ferr
}

func (g *Group) readField(state *parseState, key uint16, value []byte) error {
	var err error
	switch key {
	case 0x0000:
		// ignore
	case groupIDField:
		if err = verifyFieldSize("group ID", value, 4); err != nil {
			return err
		}
		id := binary.LittleEndian.Uint32(value)
		state.groups[id] = g
		g.ID = id
	case groupNameField:
		g.Name = string(stripNull(value))
	case groupCreationTimeField:
		g.CreationTime, err = readDate("group creation time", value)
	case groupLastModificationTimeField:
		g.LastModificationTime, err = readDate("group modification time", value)
	case groupLastAccessTimeField:
		g.LastAccessTime, err = readDate("group access time", value)
	case groupExpiryTimeField:
		g.ExpiryTime, err = readDate("group expiry time", value)
	case groupIconField:
		if err = verifyFieldSize("group icon", value, 4); err != nil {
			return err
		}
		g.Icon = Icon(binary.LittleEndian.Uint32(value))
	case groupLevelField:
		if err = verifyFieldSize("group level", value, 2); err != nil {
			return err
		}
		state.groupLevels[g] = binary.LittleEndian.Uint16(value)
	case groupFlagsField:
		// ignore flags field
	default:
		return fmt.Errorf("keepass: unknown group field %04x", key)
	}
	return err
}

func (g *Group) write(w io.Writer, level int) error {
	ww := &writer{w: w}
	writeUint32Field(ww, groupIDField, g.ID)
	writeStringField(ww, groupNameField, g.Name)
	writeDateField(ww, groupCreationTimeField, g.CreationTime)
	writeDateField(ww, groupLastModificationTimeField, g.LastModificationTime)
	writeDateField(ww, groupLastAccessTimeField, g.LastAccessTime)
	writeDateField(ww, groupExpiryTimeField, g.ExpiryTime)
	writeUint32Field(ww, groupIconField, uint32(g.Icon))
	writeUint16Field(ww, groupLevelField, uint16(level))
	writeUint32Field(ww, groupFlagsField, 0)
	writeField(ww, fieldTerminator, []byte{})
	return ww.err
}

func (e *Entry) read(state *parseState, r io.Reader) error {
	fr := newFieldReader(r)
	var ferr error
	for {
		k, v, err := fr.next()
		if err == io.EOF {
			return ferr
		} else if err != nil {
			return err
		}
		if ferr == nil {
			ferr = e.readField(state, k, v)
		}
	}
}

func (e *Entry) readField(state *parseState, key uint16, value []byte) error {
	var err error
	switch key {
	case 0x0000:
		// ignore field
	case entryUUIDField:
		if err = verifyFieldSize("entry UUID", value, 16); err != nil {
			return err
		}
		// TODO(light): use UUID for icons
		copy(e.UUID[:], value)
	case entryGroupIDField:
		if err = verifyFieldSize("entry group ID", value, 4); err != nil {
			return err
		}
		state.entryGroupIDs[e] = binary.LittleEndian.Uint32(value)
	case entryIconField:
		if err = verifyFieldSize("entry icon", value, 4); err != nil {
			return err
		}
		e.Icon = Icon(binary.LittleEndian.Uint32(value))
	case entryTitleField:
		e.Title = string(stripNull(value))
	case entryURLField:
		e.URL = string(stripNull(value))
	case entryUsernameField:
		e.Username = string(stripNull(value))
	case entryPasswordField:
		e.Password = string(stripNull(value))
	case entryNotesField:
		// TODO(light): parsing
		e.Notes = string(stripNull(value))
	case entryCreationTimeField:
		e.CreationTime, err = readDate("entry creation time", value)
	case entryLastModificationTimeField:
		e.LastModificationTime, err = readDate("entry modification time", value)
	case entryLastAccessTimeField:
		e.LastAccessTime, err = readDate("entry access time", value)
	case entryExpiryTimeField:
		e.ExpiryTime, err = readDate("entry expiry time", value)
	case entryAttachmentNameField:
		e.Attachment.Name = string(stripNull(value))
	case entryAttachmentDataField:
		e.Attachment.Data = make([]byte, len(value))
		copy(e.Attachment.Data, value)
	default:
		return fmt.Errorf("keepass: unknown entry field %04x", key)
	}
	return err
}

func (e *Entry) write(w io.Writer, gid uint32) error {
	ww := &writer{w: w}
	writeField(ww, entryUUIDField, e.UUID[:])
	writeUint32Field(ww, entryGroupIDField, gid)
	writeUint32Field(ww, entryIconField, uint32(e.Icon))
	writeStringField(ww, entryTitleField, e.Title)
	writeStringField(ww, entryURLField, e.URL)
	writeStringField(ww, entryUsernameField, e.Username)
	writeStringField(ww, entryPasswordField, e.Password)
	// TODO(light): add in parsed info to notes
	writeStringField(ww, entryNotesField, e.Notes)
	writeDateField(ww, entryCreationTimeField, e.CreationTime)
	writeDateField(ww, entryLastModificationTimeField, e.LastModificationTime)
	writeDateField(ww, entryLastAccessTimeField, e.LastAccessTime)
	writeDateField(ww, entryExpiryTimeField, e.ExpiryTime)
	if e.HasAttachment() {
		writeStringField(ww, entryAttachmentNameField, e.Attachment.Name)
		writeField(ww, entryAttachmentDataField, e.Attachment.Data)
	} else {
		writeStringField(ww, entryAttachmentNameField, "")
		writeField(ww, entryAttachmentDataField, nil)
	}
	writeField(ww, fieldTerminator, []byte{})
	return ww.err
}

// Field types
const (
	groupIDField                   = 0x0001
	groupNameField                 = 0x0002
	groupCreationTimeField         = 0x0003
	groupLastModificationTimeField = 0x0004
	groupLastAccessTimeField       = 0x0005
	groupExpiryTimeField           = 0x0006
	groupIconField                 = 0x0007
	groupLevelField                = 0x0008
	groupFlagsField                = 0x0009

	entryUUIDField                 = 0x0001
	entryGroupIDField              = 0x0002
	entryIconField                 = 0x0003
	entryTitleField                = 0x0004
	entryURLField                  = 0x0005
	entryUsernameField             = 0x0006
	entryPasswordField             = 0x0007
	entryNotesField                = 0x0008
	entryCreationTimeField         = 0x0009
	entryLastModificationTimeField = 0x000a
	entryLastAccessTimeField       = 0x000b
	entryExpiryTimeField           = 0x000c
	entryAttachmentNameField       = 0x000d
	entryAttachmentDataField       = 0x000e

	fieldTerminator = 0xffff
)

func decryptDatabase(crypt []byte, p *kdbcrypt.Params, contentHash []byte) ([]byte, error) {
	if len(crypt)%kdbcrypt.BlockSize != 0 {
		return nil, errDatabaseUnaligned
	}
	dec, err := kdbcrypt.NewDecrypter(bytes.NewReader(crypt), p)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	plain, err := ioutil.ReadAll(io.TeeReader(dec, hash))
	if err != nil {
		// TODO(light): is this always right? padding is most likely.
		return nil, ErrHashMismatch
	}
	computed := hash.Sum(nil)
	if !bytes.Equal(computed, contentHash) {
		return nil, ErrHashMismatch
	}
	return plain, nil
}

// Encryption flags
const (
	rijndaelFlag uint32 = 2
	twofishFlag  uint32 = 8
)

// File header magic numbers
const (
	magic1 = 0x9aa2d903
	magic2 = 0xb54bfb65

	fileVersion             = 0x00030002
	fileVersionCriticalMask = 0xffffff00
)

// headerSize is the number of bytes that the file header occupies.
const headerSize = 124

func makeEncryptionFlags(p *kdbcrypt.Params) uint32 {
	switch p.Cipher {
	case kdbcrypt.RijndaelCipher:
		return rijndaelFlag
	case kdbcrypt.TwofishCipher:
		return twofishFlag
	default:
		return 0
	}
}

// header stores the non-magic values of a file header.
type header struct {
	encryptionFlags uint32
	masterSeed      [16]byte
	encryptionIV    [16]byte
	numGroups       uint32
	numEntries      uint32
	contentHash     [32]byte
	transformSeed   [32]byte
	transformRounds uint32
}

func (h *header) cipher() (kdbcrypt.Cipher, error) {
	switch {
	case h.encryptionFlags&rijndaelFlag != 0:
		return kdbcrypt.RijndaelCipher, nil
	case h.encryptionFlags&twofishFlag != 0:
		return kdbcrypt.TwofishCipher, nil
	default:
		return 0, ErrUnknownEncryption
	}
}

// initCryptParams returns kdbcrypt parameters for an existing database.
func (h *header) initCryptParams(p *kdbcrypt.Params, password, keyFileHash []byte) error {
	var err error
	p.Cipher, err = h.cipher()
	if err != nil {
		return err
	}
	p.IV = h.encryptionIV
	p.Key = kdbcrypt.Key{
		Password:        password,
		KeyFileHash:     keyFileHash,
		MasterSeed:      h.masterSeed,
		TransformSeed:   h.transformSeed,
		TransformRounds: h.transformRounds,
	}
	p.ComputedKey = p.Key.Compute()
	return nil
}

// initComputedCryptParams returns kdbcrypt parameters for an existing database with a computed key.
func (h *header) initComputedCryptParams(p *kdbcrypt.Params, computed kdbcrypt.ComputedKey) error {
	var err error
	p.Cipher, err = h.cipher()
	if err != nil {
		return err
	}
	p.IV = h.encryptionIV
	p.ComputedKey = computed
	p.Key = kdbcrypt.Key{
		MasterSeed:      h.masterSeed,
		TransformSeed:   h.transformSeed,
		TransformRounds: h.transformRounds,
	}
	return nil
}

func (h *header) read(r io.Reader) error {
	rr := reader{r: r}
	signature1 := rr.readUint32()
	signature2 := rr.readUint32()
	h.encryptionFlags = rr.readUint32()
	version := rr.readUint32()
	rr.readFull(h.masterSeed[:])
	rr.readFull(h.encryptionIV[:])
	h.numGroups = rr.readUint32()
	h.numEntries = rr.readUint32()
	rr.readFull(h.contentHash[:])
	rr.readFull(h.transformSeed[:])
	h.transformRounds = rr.readUint32()
	if rr.err != nil {
		return rr.err
	}
	if signature1 != magic1 || signature2 != magic2 {
		return ErrWrongSignature
	}
	if version&fileVersionCriticalMask != fileVersion&fileVersionCriticalMask {
		return ErrWrongVersion
	}
	return nil
}

func (h *header) write(w io.Writer) error {
	ww := writer{w: w}
	ww.writeUint32(magic1)
	ww.writeUint32(magic2)
	ww.writeUint32(h.encryptionFlags)
	ww.writeUint32(fileVersion)
	ww.write(h.masterSeed[:])
	ww.write(h.encryptionIV[:])
	ww.writeUint32(h.numGroups)
	ww.writeUint32(h.numEntries)
	ww.write(h.contentHash[:])
	ww.write(h.transformSeed[:])
	ww.writeUint32(h.transformRounds)
	return ww.err
}

// Errors
var (
	ErrHashMismatch      = errors.New("keepass: password does not match or database is corrupt")
	ErrWrongSignature    = errors.New("keepass: not a KeePass file")
	ErrWrongVersion      = errors.New("keepass: unsupported version")
	ErrUnknownEncryption = errors.New("keepass: unknown encryption algorithm")
)

// Data validation errors
var (
	errDatabaseUnaligned  = errors.New("keepass: database does not match block size")
	errGroupsInconsistent = errors.New("keepass: inconsistent group tree")
)
