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
	"io"
	"os"
)

// TODO(light): rotate files

// storage manages I/O to a single file.  Only one operation (reading or
// writing) can be performed at a time.
type storage struct {
	f    *os.File
	path string
}

// newStorage creates a storage that points to path.  The file will be
// created on the first write if it does not exist.
func newStorage(path string) (*storage, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return &storage{f: f, path: path}, nil
}

// exists reports whether the file exists yet.
func (st *storage) exists() bool {
	return st.f != nil
}

// reader returns a reader to the file.
func (st *storage) reader() (io.Reader, error) {
	if st.f == nil {
		return nil, &os.PathError{
			Op:   "open",
			Path: st.path,
			Err:  os.ErrNotExist,
		}
	}
	if _, err := st.f.Seek(0, os.SEEK_SET); err != nil {
		return nil, err
	}
	return st.f, nil
}

// writer opens a writer to the file by either creating or truncating it.
// Closing the returned writer will sync it to disk.
func (st *storage) writer() (io.WriteCloser, error) {
	var err error
	if st.f == nil {
		st.f, err = os.OpenFile(st.path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		return syncWriter{st.f}, nil
	}
	if _, err = st.f.Seek(0, os.SEEK_SET); err != nil {
		return nil, err
	}
	if err = st.f.Truncate(0); err != nil {
		return nil, err
	}
	return syncWriter{st.f}, nil
}

func (st *storage) Close() error {
	if st.f == nil {
		return nil
	}
	return st.f.Close()
}

type syncWriter struct {
	f *os.File
}

func (w syncWriter) Write(p []byte) (int, error) {
	return w.f.Write(p)
}

func (w syncWriter) Close() error {
	return w.f.Sync()
}
