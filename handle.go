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
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"zombiezen.com/go/sandpass/pkg/sandstormhdr"
	"zombiezen.com/go/sandpass/third_party/responsestats"
)

var (
	staticDir        = flag.String("static_dir", ".", "path to static resources (should be the project directory for development)")
	maxRequestSize   = flag.Int64("max_request_size", 2<<20, "number of bytes to limit requests to")
	checkPermissions = flag.Bool("permissions", true, "whether to check Sandstorm permissions (can be disabled for development)")
	xsrfTokenSize    = flag.Int("xsrf_token_size", 33, "size of the XSRF tokens sent to the client (in bytes)")
)

// staticFileHandler serves a file from the static directory.
type staticFileHandler string

func (h staticFileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !(r.Method == "GET" || r.Method == "HEAD") {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, filepath.Join(*staticDir, string(h)))
}

type appHandler struct {
	f    func(http.ResponseWriter, *http.Request) error
	perm string
}

func (ah appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if *checkPermissions && ah.perm != "" && !sandstormhdr.HasPermission(r.Header, ah.perm) {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, *maxRequestSize)
	if err := parseMultipartForm(r); err != nil {
		log.Printf("%s %s fail form parse: %v", r.Method, r.URL.Path, err)
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}
	if !(r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
		if err := checkXSRF(r); err != nil {
			log.Printf("%s %s client error: %v", r.Method, r.URL.Path, err)
			http.Error(w, userErrorMessage(err), errorStatusCode(err))
			return
		}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	stats := responsestats.New(w)
	err := ah.f(stats, r)
	if err != nil {
		if userErrorMessage(err) == "" {
			log.Printf("%s %s server error: %v", r.Method, r.URL.Path, err)
		} else {
			log.Printf("%s %s client error: %v", r.Method, r.URL.Path, err)
		}
		if code, u := errorRedirect(err); u != "" {
			http.Redirect(w, r, u, code)
			return
		}
		if stats.StatusCode() == 0 {
			msg := userErrorMessage(err)
			if msg == "" {
				msg = "internal server error; check logs"
			}
			http.Error(w, msg, errorStatusCode(err))
		}
	}
}

func parseMultipartForm(r *http.Request) error {
	err := r.ParseMultipartForm(*maxRequestSize)
	if err == http.ErrNotMultipart {
		return nil
	}
	if err != nil {
		return err
	}
	if err := r.MultipartForm.RemoveAll(); err != nil {
		// This is likely to never occur, since the request should be limited to maxRequestSize.
		log.Println("form cleanup:", err)
	}
	return nil
}

// xsrfCookie is the name of browser cookie containing the session-independent XSRF token.
const xsrfCookie = "sandpass_xsrf"

const xsrfFormName = "xsrftoken"

// xsrfToken either returns the XSRF token from the cookie or generates
// a new one and sets the XSRF cookie.
func xsrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(xsrfCookie); err == nil && c.Value != "" {
		return c.Value, nil
	} else if err != http.ErrNoCookie && err != nil {
		return "", fmt.Errorf("read xsrf token: %v", err)
	}
	buf := make([]byte, *xsrfTokenSize)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate xsrf token: %v", err)
	}
	tok := base64.StdEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:  xsrfCookie,
		Value: tok,
		Path:  "/",
	})
	return tok, nil
}

func checkXSRF(r *http.Request) error {
	c, err := r.Cookie(xsrfCookie)
	if err != nil {
		return xsrfError{err}
	} else if c.Value == "" {
		return xsrfError{fmt.Errorf("empty cookie")}
	}
	if fv := r.FormValue(xsrfFormName); fv != c.Value {
		return xsrfError{fmt.Errorf("form value %q does not match cookie %q", fv, c.Value)}
	}
	return nil
}
