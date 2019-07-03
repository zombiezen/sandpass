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
	"mime"
	"net/http"
	"net/url"
	"os"
	slashpath "path"
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
	if *dbPath == "" || sessions.keyPath == "" {
		log.Println("must specify -db and -session_key")
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
	if err := http.ListenAndServe(*listen, nil); err != nil {
		log.Println("listen:", err)
		os.Exit(1)
	}
}

func initTemplates() error {
	var err error
	tmpl, err = template.New("").Funcs(template.FuncMap{
		"emspace":     emspace,
		"route":       templateRoute,
		"sortEntries": sortEntries,
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

	r.Handle("/", appHandler{f: index}).Name("root")
	r.Handle("/search", appHandler{f: handleSearch}).Name("search")
	r.Handle("/nuke", appHandler{f: confirmNuke, perm: "init"}).Methods("GET").Name("confirmNuke")
	r.Handle("/nuke", appHandler{f: nuke, perm: "init"}).Methods("POST").Name("nuke")

	rGroupDir := r.PathPrefix("/g").Subrouter()
	rGroupDir.Handle("/", appHandler{f: listGroups}).Methods("GET").Name("listGroups")
	rGroupDir.Handle("/", appHandler{f: postGroup, perm: "write"}).Methods("POST").Name("newGroup")
	rGroupDir.Handle("/new", appHandler{f: postGroupForm, perm: "write"}).Methods("GET").Name("newGroupForm")
	rGroupDir.Handle("/{gid}", appHandler{f: viewGroup}).Methods("GET").Name("viewGroup")
	rGroupDir.Handle("/{gid}", appHandler{f: postGroup, perm: "write"}).Methods("POST").Name("editGroup")
	rGroupDir.Handle("/{gid}", appHandler{f: deleteGroup, perm: "write"}).Methods("DELETE")
	rGroup := rGroupDir.PathPrefix("/{gid}").Subrouter()
	rGroup.Handle("/edit", appHandler{f: postGroupForm, perm: "write"}).Methods("GET").Name("editGroupForm")
	rGroup.Handle("/delete", appHandler{f: confirmDeleteGroup, perm: "write"}).Methods("GET").Name("confirmDeleteGroup")
	rGroup.Handle("/delete", appHandler{f: deleteGroup, perm: "write"}).Methods("POST").Name("deleteGroup")

	rEntryDir := r.PathPrefix("/entry").Subrouter()
	rEntryDir.Handle("/", appHandler{f: postEntry, perm: "write"}).Methods("POST").Name("newEntry")
	rEntryDir.Handle("/new", appHandler{f: postEntryForm, perm: "write"}).Methods("GET").Name("newEntryForm")
	rEntryDir.Handle("/{uuid}", appHandler{f: viewEntry}).Methods("GET").Name("viewEntry")
	rEntryDir.Handle("/{uuid}", appHandler{f: postEntry, perm: "write"}).Methods("POST").Name("editEntry")
	rEntryDir.Handle("/{uuid}", appHandler{f: deleteEntry, perm: "write"}).Methods("DELETE")
	rEntry := rEntryDir.PathPrefix("/{uuid}").Subrouter()
	rEntry.Handle("/edit", appHandler{f: postEntryForm, perm: "write"}).Methods("GET").Name("editEntryForm")
	rEntry.Handle("/delete", appHandler{f: confirmDeleteEntry, perm: "write"}).Methods("GET").Name("confirmDeleteEntry")
	rEntry.Handle("/delete", appHandler{f: deleteEntry, perm: "write"}).Methods("POST").Name("deleteEntry")
	rEntry.Handle("/attachment", appHandler{f: downloadAttachment}).Methods("GET", "HEAD").Name("downloadAttachment")
	rEntry.Handle("/attachment", appHandler{f: deleteAttachment, perm: "write"}).Methods("DELETE")
	rEntry.Handle("/attachment/delete", appHandler{f: confirmDeleteAttachment, perm: "write"}).Methods("GET", "HEAD").Name("confirmDeleteAttachment")
	rEntry.Handle("/attachment/delete", appHandler{f: deleteAttachment, perm: "write"}).Methods("POST").Name("deleteAttachment")

	meta := r.PathPrefix("/_").Subrouter()
	meta.Handle("/newdb", appHandler{f: newDB, perm: "init"}).Methods("POST").Name("newDB")
	meta.Handle("/start", appHandler{f: startSession}).Methods("POST").Name("startSession")
	meta.Handle("/pwgen", appHandler{f: pwgen}).Methods("GET").Name("pwgen")

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

func requestGroup(db *keepass.Database, vars map[string]string) (*keepass.Group, error) {
	if vars["gid"] == "" {
		return nil, nil
	}
	gid, err := strconv.ParseUint(vars["gid"], 10, 32)
	if err != nil {
		return nil, notFoundError{}
	}
	g := db.FindGroup(uint32(gid))
	if g == nil {
		return nil, notFoundError{}
	}
	return g, nil
}

func requestEntry(db *keepass.Database, vars map[string]string) (*keepass.Entry, error) {
	if vars["uuid"] == "" {
		return nil, nil
	}
	uuid, err := uuids.Parse(vars["uuid"])
	if err != nil {
		return nil, notFoundError{}
	}
	e := db.Find(uuid)
	if e == nil {
		return nil, notFoundError{}
	}
	return e, nil
}

func requestParentGroup(db *keepass.Database, form url.Values) (*keepass.Group, error) {
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
		return redirectRoute(w, r, "listGroups")
	}
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "index.html", struct {
		FirstTime   bool
		Error       string
		Permissions permissions
		XSRFToken   string
	}{
		FirstTime:   !exists,
		Error:       r.FormValue("error"),
		Permissions: requestPermissions(r),
		XSRFToken:   xtok,
	})
}

func listGroups(w http.ResponseWriter, r *http.Request) error {
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
	g, err := requestGroup(db, mux.Vars(r))
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "group.html", struct {
		Group       *keepass.Group
		Permissions permissions
	}{
		Group:       g,
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
	e, err := requestEntry(db, mux.Vars(r))
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "entry.html", struct {
		Entry       *keepass.Entry
		Group       *keepass.Group
		Permissions permissions
	}{
		Entry:       e,
		Group:       e.Parent(),
		Permissions: requestPermissions(r),
	})
}

func downloadAttachment(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	e, err := requestEntry(db, mux.Vars(r))
	if err != nil {
		return err
	}
	if !e.HasAttachment() {
		return notFoundError{}
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", e.Attachment.Name))
	w.Header().Set("Content-Length", strconv.Itoa(len(e.Attachment.Data)))
	contentType := mime.TypeByExtension(slashpath.Ext(e.Attachment.Name))
	if contentType == "" {
		// http.DetectContentType always returns a valid MIME type.
		contentType = http.DetectContentType(e.Attachment.Data)
	}
	w.Header().Set("Content-Type", contentType)
	_, err = w.Write(e.Attachment.Data)
	return err
}

func postEntryForm(w http.ResponseWriter, r *http.Request) error {
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	e, err := requestEntry(db, mux.Vars(r))
	if err != nil {
		return err
	}
	var parent *keepass.Group
	if e == nil {
		e = new(keepass.Entry)
		parent, err = requestParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		if parent.IsRoot() {
			return invalidParentError{r.Form.Get("parent")}
		}
	} else {
		parent = e.Parent()
	}
	return tmpl.ExecuteTemplate(w, "editentry.html", struct {
		Entry         *keepass.Entry
		Group         *keepass.Group
		ParentOptions []groupItem
		XSRFToken     string
	}{
		Entry:         e,
		Group:         parent,
		ParentOptions: flattenGroups(nil, db.Root(), 0, nil),
		XSRFToken:     xtok,
	})
}

func postEntry(w http.ResponseWriter, r *http.Request) error {
	now := time.Now()
	if err := parseMultipartForm(r); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	var e *keepass.Entry
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		e, err = requestEntry(db, mux.Vars(r))
		if err != nil {
			return err
		}
		newParent, err := requestParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		if e == nil {
			e, err = newParent.NewEntry()
			if err != nil {
				return err
			}
			e.TimeInfo = keepass.TimeInfo{
				CreationTime:   now,
				LastAccessTime: now,
			}
		} else if parent := e.Parent(); newParent != parent {
			if err := e.SetParent(newParent); err != nil {
				return err
			}
		}
		e.Title = r.FormValue("title")
		e.Username = r.FormValue("username")
		e.Password = r.FormValue("password")
		e.URL = r.FormValue("url")
		if f, header, err := r.FormFile("attachment"); err == nil {
			e.Attachment.Name = header.Filename
			e.Attachment.Data, err = ioutil.ReadAll(f)
			if err != nil {
				return err
			}
		} else if err != http.ErrMissingFile {
			return err
		}
		e.Notes = r.FormValue("notes")
		e.LastModificationTime = now
		return nil
	})
	if err != nil {
		return err
	}
	return redirectRoute(w, r, "viewEntry", "uuid", e.UUID.String())
}

func confirmDeleteAttachment(w http.ResponseWriter, r *http.Request) error {
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	e, err := requestEntry(db, mux.Vars(r))
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "deleteattachment.html", struct {
		Entry     *keepass.Entry
		Group     *keepass.Group
		XSRFToken string
	}{
		Entry:     e,
		Group:     e.Parent(),
		XSRFToken: xtok,
	})
}

func deleteAttachment(w http.ResponseWriter, r *http.Request) error {
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	var e *keepass.Entry
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		e, err = requestEntry(db, mux.Vars(r))
		if err != nil {
			return err
		}
		if !e.HasAttachment() {
			return notFoundError{}
		}
		e.Attachment.Name = ""
		e.Attachment.Data = nil
		e.LastModificationTime = now
		return nil
	})
	if err != nil {
		return err
	}
	return redirectRoute(w, r, "viewEntry", "uuid", e.UUID.String())
}

func confirmDeleteEntry(w http.ResponseWriter, r *http.Request) error {
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	e, err := requestEntry(db, mux.Vars(r))
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "deleteentry.html", struct {
		Entry     *keepass.Entry
		Group     *keepass.Group
		XSRFToken string
	}{
		Entry:     e,
		Group:     e.Parent(),
		XSRFToken: xtok,
	})
}

func deleteEntry(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	var parent *keepass.Group
	err := transaction(w, r, func(db *keepass.Database) error {
		e, err := requestEntry(db, mux.Vars(r))
		if err != nil {
			return err
		}
		parent = e.Parent()
		parent.RemoveEntry(e)
		return nil
	})
	if err != nil {
		return err
	}
	if r.Method == "DELETE" {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	return redirectRoute(w, r, "viewGroup", "gid", strconv.FormatUint(uint64(parent.ID), 10))
}

func postGroupForm(w http.ResponseWriter, r *http.Request) error {
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	g, err := requestGroup(db, mux.Vars(r))
	if err != nil {
		return err
	}
	var params struct {
		Group         *keepass.Group
		Parent        *keepass.Group
		NewGroup      bool
		ParentOptions []groupItem
		XSRFToken     string
	}
	params.XSRFToken = xtok
	var exclude func(*keepass.Group) bool
	if g == nil {
		params.Group = new(keepass.Group)
		parent, err := requestParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		params.Parent = parent
		params.NewGroup = true
	} else {
		params.Group = g
		params.Parent = g.Parent()
		exclude = func(gg *keepass.Group) bool { return gg == g }
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
	var g *keepass.Group
	err := transaction(w, r, func(db *keepass.Database) error {
		var err error
		g, err = requestGroup(db, mux.Vars(r))
		if err != nil {
			return err
		}
		newParent, err := requestParentGroup(db, r.Form)
		if err != nil {
			return err
		}
		if g == nil {
			g = newParent.NewSubgroup()
			g.TimeInfo = keepass.TimeInfo{
				CreationTime:   now,
				LastAccessTime: now,
			}
		} else if parent := g.Parent(); newParent != parent {
			if err := g.SetParent(newParent); err != nil {
				return err
			}
		}
		g.Name = r.FormValue("name")
		g.LastModificationTime = now
		return nil
	})
	if err != nil {
		return err
	}
	return redirectRoute(w, r, "viewGroup", "gid", strconv.FormatUint(uint64(g.ID), 10))
}

func confirmDeleteGroup(w http.ResponseWriter, r *http.Request) error {
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	g, err := requestGroup(db, mux.Vars(r))
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "deletegroup.html", struct {
		Group     *keepass.Group
		XSRFToken string
	}{
		Group:     g,
		XSRFToken: xtok,
	})
}

func deleteGroup(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	err := transaction(w, r, func(db *keepass.Database) error {
		g, err := requestGroup(db, mux.Vars(r))
		if err != nil {
			return err
		}
		return g.Parent().RemoveSubgroup(g)
	})
	if err != nil {
		return err
	}
	if r.Method == "DELETE" {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	return redirectRoute(w, r, "listGroups")
}

func confirmNuke(w http.ResponseWriter, r *http.Request) error {
	xtok, err := xsrfToken(w, r)
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, "nuke.html", struct {
		XSRFToken string
	}{
		XSRFToken: xtok,
	})
}

func nuke(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	if err := dbStorage.remove(); err != nil {
		return err
	}
	if err := sessions.invalidateAll(); err != nil {
		return err
	}
	return redirectRoute(w, r, "root")
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

	_, err = sessions.new(w, sessionData{
		Key: db.ComputedKey(),
	})
	if err != nil {
		return err
	}
	return redirectRoute(w, r, "listGroups")
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

	_, err = sessions.new(w, sessionData{
		Key: db.ComputedKey(),
	})
	if err != nil {
		return err
	}
	return redirectRoute(w, r, "listGroups")
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

func templateRoute(name string, pairs ...interface{}) (template.URL, error) {
	r := router.Get(name)
	if r == nil {
		return "", fmt.Errorf("no route found for %q", name)
	}
	var s []string
	if len(pairs) != 0 {
		s = make([]string, len(pairs))
		for i := range pairs {
			s[i] = fmt.Sprint(pairs[i])
		}
	}
	u, err := r.URLPath(s...)
	if err != nil {
		return "", fmt.Errorf("route %q: %v", name, err)
	}
	return template.URL(u.String()), nil
}

func redirectRoute(w http.ResponseWriter, r *http.Request, name string, pairs ...string) error {
	route := router.Get(name)
	if route == nil {
		return fmt.Errorf("redirect: no route %q", name)
	}
	u, err := route.URL(pairs...)
	if err != nil {
		return fmt.Errorf("redirect: route %q: %v", name, err)
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
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
	if !*checkPermissions {
		return true
	}
	for _, perm := range p {
		if perm == name {
			return true
		}
	}
	return false
}
