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
	"net/http"
	"unicode"

	"golang.org/x/text/language"
	textsearch "golang.org/x/text/search"

	"zombiezen.com/go/sandpass/pkg/keepass"
)

func handleSearch(w http.ResponseWriter, r *http.Request) error {
	mu.Lock()
	defer mu.Unlock()
	db, err := sessions.dbFromRequest(w, r)
	if err != nil {
		return err
	}
	var data struct {
		Query   string
		Results []*keepass.Entry
	}
	data.Query = r.FormValue("q")
	pq := parseQuery(data.Query)
	if pq == nil {
		data.Query = ""
	} else {
		data.Results = search(db, pq)
	}
	return tmpl.ExecuteTemplate(w, "search.html", data)
}

func search(db *keepass.Database, q *parsedQuery) []*keepass.Entry {
	var results []*keepass.Entry
	for _, e := range db.Entries() {
		if q.matchesText(e.Title) {
			results = append(results, e)
		}
	}
	return results
}

type parsedQuery struct {
	pats []*textsearch.Pattern
}

func parseQuery(query string) *parsedQuery {
	if len(query) == 0 {
		return nil
	}
	var words []string
	start := -1
	for i, r := range query {
		space := unicode.IsSpace(r)
		if space && start != -1 {
			words = append(words, query[start:i])
			start = -1
		} else if !space && start == -1 {
			start = i
		}
	}
	if start != -1 {
		words = append(words, query[start:])
	}
	if len(words) == 0 {
		return nil
	}
	m := textsearch.New(language.Und, textsearch.Loose)
	if len(words) == 1 {
		return &parsedQuery{pats: []*textsearch.Pattern{m.CompileString(query)}}
	}
	pq := &parsedQuery{pats: make([]*textsearch.Pattern, len(words))}
	for i := range words {
		pq.pats[i] = m.CompileString(words[i])
	}
	return pq
}

func (pq *parsedQuery) matchesText(s string) bool {
	if pq == nil || len(pq.pats) == 0 {
		return false
	}
	for _, pat := range pq.pats {
		if start, _ := pat.IndexString(s); start == -1 {
			return false
		}
	}
	return true
}
