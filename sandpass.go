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

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"zombiezen.com/go/sandpass/pkg/keepass"
	"zombiezen.com/go/sandpass/pkg/sandstormhdr"
	"zombiezen.com/go/sandpass/pkg/uuids"
)

var (
	listen       = flag.String("listen", "[::]:8080", "address to listen on")
	dbPath       = flag.String("db", "", "path to database")
	templatesDir = flag.String("templates_dir", "templates", "path to template directory")
	sessionGC    = flag.Duration("session_gc", 1*time.Minute, "frequency at which sessions are to be cleared from memory after expiring")
)

// Read-only globals
var (
	tmpl   *template.Template
	router *mux.Router
)

// Global state protected by mu.
var (
	mu        sync.Mutex
	sessions  sessionStorage
	dbStorage *storage
)

func main() {
	flag.Parse()
	if *dbPath == "" {
		log.Println("must specify -db")
		os.Exit(1)
	}

	if err := initTemplates(); err != nil {
		log.Println("failed to parse templates:", err)
		os.Exit(1)
	}
	if err := initDatabase(); err != nil {
		// TODO(light): present recovery options to user instead
		log.Println("open database:", err)
		os.Exit(1)
	}
	initHandlers()
	go gcSessions()
	if err := http.ListenAndServe(*listen, nil); err != nil {
		log.Println("listen:", err)
		os.Exit(1)
	}
}

func initTemplates() error {
	var err error
	tmpl, err = template.New("").Funcs(template.FuncMap{
		"sortEntries": sortEntries,
		"emspace":     emspace,
	}).ParseGlob(filepath.Join(*templatesDir, "*.html"))
	return err
}

func initDatabase() error {
	var err error
	dbStorage, err = newStorage(*dbPath)
	return err
}

func initHandlers() {
	r := mux.NewRouter()

	// App handlers
	r.Handle("/", appHandler{f: index})
	r.Handle("/search", appHandler{f: handleSearch})
	r.Handle("/groups", appHandler{f: groupList}).Name("listGroups")
	r.Handle("/newgroup", appHandler{f: postGroupForm, perm: "write"}).Methods("GET")
	r.Handle("/newgroup", appHandler{f: postGroup, perm: "write"}).Methods("POST")
	r.Handle("/nuke", appHandler{f: confirmNuke, perm: "init"}).Methods("GET")
	r.Handle("/nuke", appHandler{f: nuke, perm: "init"}).Methods("POST")
	r.Handle("/groups/{gid}", appHandler{f: viewGroup}).Name("viewGroup").Methods("GET")
	r.Handle("/groups/{gid}", appHandler{f: deleteGroup, perm: "write"}).Methods("DELETE")
	rGroup := r.PathPrefix("/groups/{gid}").Subrouter()
	rGroup.Handle("/edit", appHandler{f: postGroupForm, perm: "write"}).Methods("GET")
	rGroup.Handle("/edit", appHandler{f: postGroup, perm: "write"}).Methods("POST")
	rGroup.Handle("/delete", appHandler{f: confirmDeleteGroup, perm: "write"}).Methods("GET")
	rGroup.Handle("/delete", appHandler{f: deleteGroup, perm: "write"}).Methods("POST")
	rGroup.Handle("/newentry", appHandler{f: postEntryForm, perm: "write"}).Methods("GET")
	rGroup.Handle("/newentry", appHandler{f: postEntry, perm: "write"}).Methods("POST")
	rGroup.Handle("/entry/{uuid}", appHandler{f: viewEntry}).Name("viewEntry").Methods("GET")
	rGroup.Handle("/entry/{uuid}", appHandler{f: deleteEntry, perm: "write"}).Methods("DELETE")
	rEntry := rGroup.PathPrefix("/entry/{uuid}").Subrouter()
	rEntry.Handle("/edit", appHandler{f: postEntryForm, perm: "write"}).Methods("GET")
	rEntry.Handle("/edit", appHandler{f: postEntry, perm: "write"}).Methods("POST")
	rEntry.Handle("/delete", appHandler{f: confirmDeleteEntry, perm: "write"}).Methods("GET")
	rEntry.Handle("/delete", appHandler{f: deleteEntry, perm: "write"}).Methods("POST")
	meta := r.PathPrefix("/_").Subrouter()
	meta.Handle("/newdb", appHandler{f: newDB, perm: "init"}).Methods("POST")
	meta.Handle("/start", appHandler{f: startSession}).Methods("POST")
	meta.Handle("/pwgen", appHandler{f: pwgen}).Methods("GET")

	// Static files
	staticFiles := []struct {
		url  string
		file string
	}{
		{"/style.css", "style.css"},
		{"/fonts/Roboto-Regular.woff", "third_party/roboto/Roboto-Regular.woff"},
		{"/fonts/Roboto-Bold.woff", "third_party/roboto/Roboto-Bold.woff"},
		{"/js/clipboard.js", "third_party/clipboard.js/dist/clipboard.min.js"},
		{"/js/editentry.js", "js/editentry.js"},
		{"/js/entry.js", "js/entry.js"},
		{"/js/init.js", "js/init.js"},
	}
	for _, sf := range staticFiles {
		r.Handle(sf.url, staticFileHandler(sf.file))
	}

	http.Handle("/", r)
	router = r
}

func gcSessions() {
	tick := time.Tick(*sessionGC)
	for {
		<-tick
		mu.Lock()
		n := sessions.clearInvalid()
		mu.Unlock()
		if n > 0 {
			log.Printf("cleared %d invalid sessions", n)
		}
	}
}

type requestParams struct {
	g *keepass.Group
	e *keepass.Entry
}

func extractRequestParams(db *keepass.Database, r *http.Request) (requestParams, error) {
	v := mux.Vars(r)
	var p requestParams
	if v["gid"] != "" {
		gid, err := strconv.ParseUint(v["gid"], 10, 32)
		if err != nil {
			return requestParams{}, notFoundError{}
		}
		p.g = db.FindGroup(uint32(gid))
		if p.g == nil {
			return requestParams{}, notFoundError{}
		}
	}
	if v["uuid"] != "" {
		uuid, err := uuids.Parse(v["uuid"])
		if err != nil {
			return requestParams{}, notFoundError{}
		}
		p.e = db.Find(uuid)
		if p.e == nil {
			return requestParams{}, notFoundError{}
		}
	}
	return p, nil
}

func index(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	exists := dbStorage.exists()
	hasPassword := true
	if exists {
		if _, err := openDatabase(nil); err == nil {
			hasPassword = false
		}
	}
	mu.Unlock()

	if exists && !hasPassword {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return nil
	}
	return tmpl.ExecuteTemplate(w, "index.html", struct {
		FirstTime   bool
		Error       string
		Permissions permissions
	}{
		FirstTime:   !exists,
		Error:       r.FormValue("error"),
		Permissions: requestPermissions(r),
	})
}

func groupList(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "groups.html", struct {
		Root        *keepass.Group
		Permissions permissions
	}{
		Root:        db.Root(),
		Permissions: requestPermissions(r),
	})
}

func viewGroup(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	params, err := extractRequestParams(db, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "group.html", struct {
		Group       *keepass.Group
		Permissions permissions
	}{
		Group:       params.g,
		Permissions: requestPermissions(r),
	})
}

func viewEntry(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	params, err := extractRequestParams(db, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "entry.html", struct {
		Entry       *keepass.Entry
		Group       *keepass.Group
		Permissions permissions
	}{
		Entry:       params.e,
		Group:       params.g,
		Permissions: requestPermissions(r),
	})
}

func postEntryForm(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	params, err := extractRequestParams(db, r)
	if err != nil {
		return err
	}
	if params.e == nil {
		params.e = new(keepass.Entry)
	}
	return tmpl.ExecuteTemplate(w, "editentry.html", struct {
		Entry         *keepass.Entry
		Group         *keepass.Group
		ParentOptions []groupItem
	}{
		Entry:         params.e,
		Group:         params.g,
		ParentOptions: flattenGroups(nil, db.Root(), 0, nil),
	})
}

func postEntry(w http.ResponseWriter, r *http.Request) error {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	var p requestParams
	var newParent *keepass.Group
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		p, err = extractRequestParams(db, r)
		if err != nil {
			return err
		}
		newParent, err = extractParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		if p.e == nil {
			p.e, err = p.g.NewEntry()
			if err != nil {
				return err
			}
			p.e.TimeInfo = keepass.TimeInfo{
				CreationTime:   now,
				LastAccessTime: now,
			}
		} else if parent := p.e.Parent(); newParent != parent {
			if err := p.e.SetParent(newParent); err != nil {
				return err
			}
		}
		p.e.Title = r.FormValue("title")
		p.e.Username = r.FormValue("username")
		p.e.Password = r.FormValue("password")
		p.e.URL = r.FormValue("url")
		p.e.Notes = r.FormValue("notes")
		p.e.LastModificationTime = now
		return nil
	})
	if err != nil {
		return err
	}
	u, err := router.GetRoute("viewEntry").URL(
		"gid", strconv.FormatUint(uint64(newParent.ID), 10),
		"uuid", p.e.UUID.String())
	if err != nil {
		return err
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}

func confirmDeleteEntry(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	params, err := extractRequestParams(db, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "deleteentry.html", struct {
		Entry *keepass.Entry
		Group *keepass.Group
	}{
		Entry: params.e,
		Group: params.g,
	})
}

func deleteEntry(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	var p requestParams
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		p, err = extractRequestParams(db, r)
		if err != nil {
			return err
		}
		p.g.RemoveEntry(p.e)
		return nil
	})
	if err != nil {
		return err
	}
	if r.Method == "DELETE" {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	u, err := router.GetRoute("viewGroup").URL("gid", strconv.FormatUint(uint64(p.g.ID), 10))
	if err != nil {
		return err
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}

func postGroupForm(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	rp, err := extractRequestParams(db, r)
	if err != nil {
		return err
	}
	var params struct {
		Group         *keepass.Group
		Parent        *keepass.Group
		NewGroup      bool
		ParentOptions []groupItem
	}
	var exclude func(*keepass.Group) bool
	if rp.g == nil {
		params.Group = new(keepass.Group)
		parent, err := extractParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		params.Parent = parent
		params.NewGroup = true
	} else {
		params.Group = rp.g
		params.Parent = rp.g.Parent()
		exclude = func(g *keepass.Group) bool { return g == rp.g }
	}
	root := db.Root()
	params.ParentOptions = []groupItem{{root, 0}}
	params.ParentOptions = flattenGroups(params.ParentOptions, root, 1, exclude)
	return tmpl.ExecuteTemplate(w, "editgroup.html", params)
}

func postGroup(w http.ResponseWriter, r *http.Request) error {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	var p requestParams
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		p, err = extractRequestParams(db, r)
		if err != nil {
			return err
		}
		newParent, err := extractParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		if p.g == nil {
			p.g = newParent.NewSubgroup()
			p.g.TimeInfo = keepass.TimeInfo{
				CreationTime:   now,
				LastAccessTime: now,
			}
		} else if parent := p.g.Parent(); newParent != parent {
			if err := p.g.SetParent(newParent); err != nil {
				return err
			}
		}
		p.g.Name = r.FormValue("name")
		p.g.LastModificationTime = now
		return nil
	})
	if err != nil {
		return err
	}
	u, err := router.GetRoute("viewGroup").URL("gid", strconv.FormatUint(uint64(p.g.ID), 10))
	if err != nil {
		return err
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}

func extractParentGroup(db *keepass.Database, form url.Values) (*keepass.Group, error) {
	f := form.Get("parent")
	if f == "root" {
		return db.Root(), nil
	}
	id, err := strconv.ParseUint(f, 10, 32)
	if err != nil {
		return nil, invalidParentError{f}
	}
	g := db.FindGroup(uint32(id))
	if g == nil {
		return nil, invalidParentError{f}
	}
	return g, nil
}

func confirmDeleteGroup(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	params, err := extractRequestParams(db, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "deletegroup.html", struct {
		Group *keepass.Group
	}{
		Group: params.g,
	})
}

func deleteGroup(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	var p requestParams
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		p, err = extractRequestParams(db, r)
		if err != nil {
			return err
		}
		parent := p.g.Parent()
		return parent.RemoveSubgroup(p.g)
	})
	if err != nil {
		return err
	}
	if r.Method == "DELETE" {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	u, err := router.GetRoute("listGroups").URL()
	if err != nil {
		return err
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}

func confirmNuke(w http.ResponseWriter, r *http.Request) error {
	return tmpl.ExecuteTemplate(w, "nuke.html", nil)
}

func nuke(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	if err := dbStorage.remove(); err != nil {
		return err
	}
	sessions.clear()
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func newDB(w http.ResponseWriter, r *http.Request) error {
	now := time.Now()
	password, keyfile, err := readCredentials(r)
	if err != nil {
		return err
	}
	f, _, err := r.FormFile("database")
	if err == nil {
		defer f.Close()
	} else if err != nil && err != http.ErrMissingFile {
		return err
	}

	mu.Lock()
	defer mu.Unlock()

	if dbStorage.exists() {
		return userError{
			msg: "Can't overwrite existing database.",
			err: errors.New("database exists"),
		}
	}
	var db *keepass.Database
	if f == nil {
		db, err = keepass.New(&keepass.Options{
			Password: password,
			KeyFile:  optReader(keyfile),
		})
		if err != nil {
			return err
		}
		prepopulateDB(db, now)
		if err := writeDatabase(db); err != nil {
			return err
		}
	} else if db, err = importDB(f, password, keyfile); err != nil {
		return err
	}

	sessions.new(w, sessionData{
		key: db.ComputedKey(),
	})
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
	return nil
}

func prepopulateDB(db *keepass.Database, now time.Time) {
	{
		g := db.Root().NewSubgroup()
		g.Name = "Internet"
		g.TimeInfo.CreationTime = now
		g.TimeInfo.LastModificationTime = now
	}
	{
		g := db.Root().NewSubgroup()
		g.Name = "Wi-Fi"
		g.TimeInfo.CreationTime = now
		g.TimeInfo.LastModificationTime = now
	}
	{
		g := db.Root().NewSubgroup()
		g.Name = "Misc"
		g.TimeInfo.CreationTime = now
		g.TimeInfo.LastModificationTime = now
	}
}

func importDB(f io.ReadSeeker, password string, keyfile []byte) (*keepass.Database, error) {
	db, err := keepass.Open(f, &keepass.Options{
		Password: password,
		KeyFile:  optReader(keyfile),
	})
	if err == keepass.ErrHashMismatch {
		return nil, rootRedirectError{userError{
			msg: "Unable to decrypt database. Check password and try again.",
			err: fmt.Errorf("import database: %v", err),
		}}
	} else if err != nil {
		return nil, fmt.Errorf("import database: %v", err)
	}
	if _, err = f.Seek(0, os.SEEK_SET); err != nil {
		return nil, fmt.Errorf("import database: %v", err)
	}

	dbw, err := dbStorage.writer()
	if err != nil {
		return nil, fmt.Errorf("import database: open writer: %v", err)
	}
	_, cpErr := io.Copy(dbw, f)
	closeErr := dbw.Close()
	if cpErr != nil {
		return nil, fmt.Errorf("import database: writing: %v", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("import database: writing: %v", err)
	}
	return db, nil
}

func startSession(w http.ResponseWriter, r *http.Request) error {
	password, keyfile, err := readCredentials(r)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()

	db, err := openDatabase(&keepass.Options{
		Password: password,
		KeyFile:  optReader(keyfile),
	})
	if isUserError(err) {
		return rootRedirectError{err}
	} else if err != nil {
		return err
	}

	sessions.new(w, sessionData{
		key: db.ComputedKey(),
	})
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
	return nil
}

// readCredentials gets credentials from a request.
func readCredentials(req *http.Request) (password string, keyfile []byte, err error) {
	password = req.FormValue("password")
	kf, _, err := req.FormFile("keyfile")
	if err == http.ErrMissingFile || err == http.ErrNotMultipart {
		return password, nil, nil
	} else if err != nil {
		return password, nil, err
	}
	// TODO(light): limit read
	keyfile, err = ioutil.ReadAll(kf)
	kf.Close()
	if err != nil {
		return password, keyfile, err
	}
	return password, keyfile, nil
}

// transaction opens the database, modifies it, and writes it back to disk.
// The caller must hold mu.
func transaction(w http.ResponseWriter, r *http.Request, f func(*keepass.Database) error) error {
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	err = f(db)
	if err != nil {
		return err
	}
	return writeDatabase(db)
}

func openDatabase(opts *keepass.Options) (*keepass.Database, error) {
	if !dbStorage.exists() {
		return nil, userError{
			msg: "Database does not exist.",
			err: errors.New("open database: does not exist"),
		}
	}
	r, err := dbStorage.reader()
	if err != nil {
		return nil, err
	}
	db, err := keepass.Open(r, opts)
	if err == keepass.ErrHashMismatch {
		return nil, userError{
			msg: "Could not decrypt database.  This means either the password you entered is incorrect or the database is corrupt.",
			err: errors.New("open database: " + err.Error()),
		}
	} else if err != nil {
		return nil, err
	}
	return db, nil
}

func writeDatabase(db *keepass.Database) error {
	wc, err := dbStorage.writer()
	if err != nil {
		return fmt.Errorf("write database: open: %v", err)
	}
	err = db.Write(wc)
	cerr := wc.Close()
	if err != nil {
		return fmt.Errorf("write database: %v", err)
	}
	if cerr != nil {
		return fmt.Errorf("write dtabase: close: %v", cerr)
	}
	return nil
}

type groupItem struct {
	Group  *keepass.Group
	Indent int
}

// flattenGroups returns the database's groups as a flat list.
func flattenGroups(items []groupItem, g *keepass.Group, indent int, exclude func(*keepass.Group) bool) []groupItem {
	for i := 0; i < g.NGroups(); i++ {
		sub := g.Group(i)
		if exclude != nil && exclude(sub) {
			continue
		}
		items = append(items, groupItem{sub, indent})
		items = flattenGroups(items, sub, indent+1, exclude)
	}
	return items
}

func optReader(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return bytes.NewReader(b)
}

func sortEntries(ent []*keepass.Entry) []*keepass.Entry {
	sorted := make(entriesByName, len(ent))
	copy(sorted, ent)
	sort.Sort(sorted)
	return []*keepass.Entry(sorted)
}

func emspace(n int) template.HTML {
	return template.HTML(strings.Repeat("&emsp;", n))
}

type entriesByName []*keepass.Entry

func (e entriesByName) Len() int {
	return len(e)
}

func (e entriesByName) Less(i, j int) bool {
	return e[i].Title < e[j].Title
}

func (e entriesByName) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

// permissions is a set of permissions from the X-Sandstorm-Permissions header.
type permissions []string

func requestPermissions(r *http.Request) permissions {
	return permissions(sandstormhdr.Permissions(r.Header))
}

func (p permissions) Has(name string) bool {
	for _, perm := range p {
		if perm == name {
			return true
		}
	}
	return false
}
