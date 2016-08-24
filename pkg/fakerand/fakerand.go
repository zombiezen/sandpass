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

// Package fakerand provides a deterministic PRNG, suitable for testing.
package fakerand

import (
	"encoding/base64"
	"io"
	"sync"
)

var (
	once    sync.Once
	data    []byte
	dataErr error
)

func initData() error {
	once.Do(func() {
		data, dataErr = base64.StdEncoding.DecodeString(blob)
	})
	return dataErr
}

// New returns a new reader that returns the same sequence of bytes every time.
// The reader can be used from multiple goroutines.
func New() io.Reader {
	return new(reader)
}

type reader struct {
	mu  sync.Mutex
	i   int
	off byte
}

func (r *reader) Read(p []byte) (n int, err error) {
	if err := initData(); err != nil {
		return 0, err
	}
	r.mu.Lock()
	n = copy(p, data[r.i:])
	if n == 0 {
		// Hit the end: rewind to beginning and change offset.
		r.i = 0
		r.off++
		n = copy(p, data[r.i:])
	}
	r.i += n
	for i := range p[:n] {
		p[i] += r.off
	}
	r.mu.Unlock()
	return
}

// blob is base64-encoded random obtained from /dev/urandom.
// Its value isn't important, just that it's the same for every test.
const blob = `
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`
