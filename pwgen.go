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
	// TODO(light): add/subtract from set from form
	set = append(set, upperLetters...)
	set = append(set, lowerLetters...)
	set = append(set, digits...)
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
