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

// Package cipherio provides I/O interfaces for encryption streams.
package cipherio // import "zombiezen.com/go/sandpass/pkg/cipherio"

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"

	"zombiezen.com/go/sandpass/pkg/padding"
)

type reader struct {
	r    io.Reader
	mode cipher.BlockMode
	pad  padding.Padding

	first  bool
	buf    bytes.Buffer
	rbuf   []byte
	nplain int // number of bytes in buf that have been decrypted
	err    error
}

// NewReader creates a new reader that decrypts and strips padding from r.
func NewReader(r io.Reader, mode cipher.BlockMode, pad padding.Padding) io.Reader {
	return &reader{
		r:     r,
		mode:  mode,
		pad:   pad,
		rbuf:  make([]byte, 1024),
		first: true,
	}
}

func (r *reader) Read(p []byte) (n int, err error) {
	if r.nplain > 0 {
		n = r.readPlain(p)
		return
	}
	r.growBuffer()
	if r.nplain > 0 {
		n = r.readPlain(p)
		return
	}
	return 0, r.err
}

func (r *reader) readPlain(p []byte) int {
	n := r.nplain
	if n > len(p) {
		n = len(p)
	}
	r.buf.Read(p[:n])
	r.nplain -= n
	return n
}

func (r *reader) growBuffer() {
	if r.err != nil {
		return
	}
	bs := r.mode.BlockSize()
	minSize := bs + 1
	nn, err := io.ReadAtLeast(r.r, r.rbuf, minSize-r.buf.Len())
	r.buf.Write(r.rbuf[:nn])
	bufSize := r.buf.Len()
	numExtra := bufSize % bs
	switch {
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		if numExtra != 0 || r.first && bufSize < bs {
			r.err = io.ErrUnexpectedEOF
		} else {
			r.err = io.EOF
		}
	case err != nil:
		r.err = err
	}
	if bufSize < bs {
		return
	}
	r.first = false
	r.nplain = bufSize - numExtra
	if numExtra == 0 && r.err == nil {
		// If we happened to stop reading at a block boundary, don't decrypt that block.
		// We don't know whether its the last block, so wait until the next grow to decide
		// what to do.
		r.nplain -= bs
	}
	b := r.buf.Bytes()[:r.nplain]
	r.mode.CryptBlocks(b, b)

	// Strip padding at end
	if r.err == io.EOF {
		strip, err := r.pad.Strip(b, bs)
		if err != nil {
			r.err = err
		}
		r.nplain = len(strip)
		r.buf.Truncate(r.nplain)
	}
}

type writer struct {
	w    io.Writer
	mode cipher.BlockMode
	pad  padding.Padding

	block []byte
	buf   []byte
	err   error
}

// NewWriter creates a new writer that encrypts its input and writes to w.
// Closing the writer adds the final padding but does not close w.
func NewWriter(w io.Writer, mode cipher.BlockMode, pad padding.Padding) io.WriteCloser {
	blockSize := mode.BlockSize()
	bufSize := 1024
	if blockSize > bufSize {
		bufSize = blockSize
	}
	return newWriter(w, mode, pad, bufSize)
}

func newWriter(w io.Writer, mode cipher.BlockMode, pad padding.Padding, bufSize int) io.WriteCloser {
	blockSize := mode.BlockSize()
	if blockSize > bufSize {
		panic("blockSize > bufSize")
	}
	return &writer{
		w:     w,
		mode:  mode,
		pad:   pad,
		buf:   make([]byte, bufSize),
		block: make([]byte, 0, blockSize),
	}
}

func (w *writer) Write(p []byte) (n int, err error) {
	if w.err != nil {
		return 0, w.err
	}
	bs := w.mode.BlockSize()
	if len(w.block)+len(p) <= bs {
		w.block = append(w.block, p...)
		return len(p), nil
	}
	if len(w.block) > 0 {
		blockLen := len(w.block)
		n = copy(w.block[blockLen:bs], p)
		w.block = w.block[:bs]
		// TODO(light): roll this into main loop
		w.mode.CryptBlocks(w.block, w.block)
		nn, err := w.w.Write(w.block)
		if err != nil {
			w.err = err
			if nn <= blockLen {
				nn = 0
			} else {
				n -= blockLen
			}
			return nn, err
		}
		w.block = w.block[:0]
	}
	var end int
	if extra := (len(p) - n) % bs; extra == 0 {
		end = len(p) - bs
	} else {
		end = len(p) - extra
	}
	for n < end {
		nn, err := w.writeNext(p[n:end])
		n += nn
		if err != nil {
			w.err = err
			return n, err
		}
	}
	w.block = append(w.block, p[n:]...)
	return len(p), nil
}

func (w *writer) writeNext(p []byte) (n int, err error) {
	bs := w.mode.BlockSize()
	n = len(p)
	if n > len(w.buf) {
		n = len(w.buf)
	}
	n -= n % bs
	copy(w.buf, p[:n])
	w.mode.CryptBlocks(w.buf[:n], w.buf[:n])
	return w.w.Write(w.buf[:n])
}

func (w *writer) Close() error {
	if w.err == errClosed {
		return nil
	} else if w.err != nil {
		return w.err
	}
	last := w.pad.Pad(w.block, w.mode.BlockSize())
	w.mode.CryptBlocks(last, last)
	_, err := w.w.Write(last)
	w.err = errClosed
	return err
}

var errClosed = errors.New("cipherio: write on closed writer")
