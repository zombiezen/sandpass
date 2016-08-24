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
	if data.Query != "" {
		data.Results = search(db, data.Query)
	}
	return tmpl.ExecuteTemplate(w, "search.html", data)
}

func search(db *keepass.Database, query string) []*keepass.Entry {
	pat := textsearch.New(language.Und, textsearch.Loose).CompileString(query)
	var results []*keepass.Entry
	for _, e := range db.Entries() {
		if start, _ := pat.IndexString(e.Title); start != -1 {
			results = append(results, e)
		}
	}
	return results
}
