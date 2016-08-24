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
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	digits       = "0123456789"
	specialChars = `!"#$%&'()*+,-./:;<=>?@[\]^_{|}~` + "`"

	lookalikeCharacters = "0OIl1|"
)

func pwgen(w http.ResponseWriter, r *http.Request) error {
	n, err := strconv.ParseUint(r.FormValue("n"), 10, 0)
	if err != nil {
		http.Error(w, "n must be an integer", http.StatusBadRequest)
		return nil
	}
	var password string
	switch r.FormValue("mode") {
	case "":
		if n < 1 || n > 200 {
			http.Error(w, "n must be an integer 1-200", http.StatusBadRequest)
			return nil
		}
		set := passwordCharset(r.Form)
		if len(set) == 0 {
			http.Error(w, "password character set is empty", http.StatusBadRequest)
			return nil
		}
		password, err = generatePasswordFromSet(int(n), set)
		if err != nil {
			return err
		}
	case "phrase":
		if n < 1 || n > 50 {
			http.Error(w, "n must be an integer 1-50", http.StatusBadRequest)
			return nil
		}
		possessives := r.FormValue("possessives") != ""
		password, err = generatePassphrase(int(n), possessives)
		if err != nil {
			return err
		}
	default:
		http.Error(w, "mode must be \"phrase\" or empty", http.StatusBadRequest)
		return nil
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(password)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, err = io.WriteString(w, password)
	return err
}

func passwordCharset(form url.Values) []byte {
	set := make([]byte, 0, len(upperLetters)+len(lowerLetters)+len(digits))
	if formFieldBool(form, "uppercase") {
		set = append(set, upperLetters...)
	}
	if formFieldBool(form, "lowercase") {
		set = append(set, lowerLetters...)
	}
	if formFieldBool(form, "digits") {
		set = append(set, digits...)
	}
	if formFieldBool(form, "special") {
		set = append(set, specialChars...)
	}
	if formFieldBool(form, "excludeLookalike") {
		set = subtractCharset(set, lookalikeCharacters)
	}
	return set
}

func generatePasswordFromSet(n int, set []byte) (string, error) {
	pw := make([]byte, n)
	for i := range pw {
		j, err := randInt(rand.Reader, len(set))
		if err != nil {
			return "", err
		}
		pw[i] = set[j]
	}
	return string(pw), nil
}

func generatePassphrase(numWords int, includePossessives bool) (string, error) {
	if err := initWordList(); err != nil {
		return "", err
	}
	max := len(wordList.words)
	if includePossessives {
		max += len(wordList.possessives)
	}
	var buf bytes.Buffer
	for i := 0; i < numWords; i++ {
		w, err := randInt(rand.Reader, max)
		if err != nil {
			return "", err
		}
		if i > 0 {
			buf.WriteByte(' ')
		}
		if w < len(wordList.words) {
			buf.WriteString(wordList.words[w])
		} else {
			buf.WriteString(wordList.possessives[w-len(wordList.words)])
		}
	}
	return buf.String(), nil
}

var wordsFile = flag.String("words_file", "/usr/share/dict/words", "File with words, one per line")

var wordList struct {
	once        sync.Once
	words       []string
	possessives []string
	err         error
}

func initWordList() error {
	wordList.once.Do(func() {
		wf, err := os.Open(*wordsFile)
		if err != nil {
			wordList.err = err
			return
		}
		defer wf.Close()
		ws := bufio.NewScanner(wf)
		wordList.words = make([]string, 0, 100000)
		wordList.possessives = make([]string, 0, 10000)
		for ws.Scan() {
			w := ws.Text()
			if !strings.HasSuffix(w, "'s") {
				wordList.words = append(wordList.words, w)
			} else {
				wordList.possessives = append(wordList.possessives, w)
			}
		}
		wordList.err = ws.Err()
	})
	return wordList.err
}

func randInt(r io.Reader, n int) (int, error) {
	max := big.NewInt(int64(n))
	i, err := rand.Int(r, max)
	if err != nil {
		return 0, err
	}
	return int(i.Int64()), nil
}

func subtractCharset(set []byte, sub string) []byte {
	n := 0
	for _, c := range set {
		if strings.IndexByte(sub, c) == -1 {
			set[n] = c
			n++
		}
	}
	return set[:n]
}

func formFieldBool(form url.Values, name string) bool {
	return form.Get(name) != ""
}
