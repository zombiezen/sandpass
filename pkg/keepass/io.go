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

package keepass

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

type fieldReader struct {
	r   reader
	buf []byte
}

func newFieldReader(r io.Reader) *fieldReader {
	return &fieldReader{
		r:   reader{r: r},
		buf: make([]byte, 0, 1024),
	}
}

// next returns the next field in the input.  val is valid until the
// subsequent call to next.  If there are no more fields, the error is
// io.EOF.
func (fr *fieldReader) next() (key uint16, val []byte, err error) {
	if fr.r.err != nil {
		return 0, nil, fr.r.err
	}
	key = fr.r.readUint16()
	sz := int(fr.r.readUint32())
	if cap(fr.buf) < sz {
		fr.buf = make([]byte, sz)
	}
	fr.buf = fr.buf[:sz]
	fr.r.readFull(fr.buf)
	if fr.r.err != nil {
		return 0, nil, fr.r.err
	}
	if key == fieldTerminator {
		fr.r.err = io.EOF
	}
	return key, fr.buf, fr.r.err
}

func stripNull(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == 0 {
		return b[:n-1]
	}
	return b
}

func readDate(name string, b []byte) (time.Time, error) {
	if err := verifyFieldSize(name, b, 5); err != nil {
		return time.Time{}, err
	}

	// 0        1        2        3        4
	// YYYYYYYY YYYYYYMM MMDDDDDH HHHHmmmm mmssssss
	year := int(b[0])<<6 | int(b[1]>>2)
	month := time.Month(b[1]&0x03<<2 | b[2]>>6)
	day := int(b[2] >> 1 & 0x1f)
	hour := int(b[2]&0x01<<4 | b[3]>>4)
	minute := int(b[3]&0x0f<<2 | b[4]>>6)
	second := int(b[4] & 0x3f)

	if year == 2999 && month == time.December && day == 28 && hour == 23 && minute == 59 && second == 59 {
		// Magic "never" time.
		return time.Time{}, nil
	}
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC), nil
}

type reader struct {
	r   io.Reader
	err error
}

func (r *reader) readFull(p []byte) {
	if r.err != nil {
		return
	}
	_, r.err = io.ReadFull(r.r, p)
}

func (r *reader) readUint16() uint16 {
	if r.err != nil {
		return 0
	}
	var buf [2]byte
	_, r.err = io.ReadFull(r.r, buf[:])
	if r.err != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(buf[:])
}

func (r *reader) readUint32() uint32 {
	if r.err != nil {
		return 0
	}
	var buf [4]byte
	_, r.err = io.ReadFull(r.r, buf[:])
	if r.err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(buf[:])
}

type writer struct {
	w   io.Writer
	err error
}

func (w *writer) write(p []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.w.Write(p)
}

func (w *writer) writeUint16(i uint16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], i)
	w.write(buf[:])
}

func (w *writer) writeUint32(i uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], i)
	w.write(buf[:])
}

func writeField(w *writer, key uint16, val []byte) {
	w.writeUint16(key)
	w.writeUint32(uint32(len(val)))
	w.write(val)
}

func writeUint16Field(w *writer, key uint16, val uint16) {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], val)
	writeField(w, key, buf[:])
}

func writeUint32Field(w *writer, key uint16, val uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], val)
	writeField(w, key, buf[:])
}

func writeStringField(w *writer, key uint16, s string) {
	buf := make([]byte, len(s)+1) // null byte at end
	copy(buf, s)
	writeField(w, key, buf)
}

func writeDateField(w *writer, key uint16, t time.Time) {
	var (
		year   int
		month  time.Month
		day    int
		hour   int
		minute int
		second int
	)
	if t.IsZero() {
		year = 2999
		month = time.December
		day = 28
		hour = 23
		minute = 59
		second = 59
	} else {
		t = t.In(time.UTC)
		year = t.Year()
		month = t.Month()
		day = t.Day()
		hour = t.Hour()
		minute = t.Minute()
		second = t.Second()
	}
	var b [5]byte
	b[0] = byte(year >> 6)
	b[1] = byte(year&0x3f)<<2 | byte(month)>>2
	b[2] = byte(month&0x03)<<6 | byte(day<<1) | byte(hour>>4)
	b[3] = byte(hour&0x0f<<4) | byte(minute>>2)
	b[4] = byte(minute&0x03<<6) | byte(second)
	writeField(w, key, b[:])
}

func verifyFieldSize(name string, val []byte, want int) error {
	n := len(val)
	if n != want {
		return fieldSizeError{name, n, want}
	}
	return nil
}

type fieldSizeError struct {
	name string
	size int
	want int
}

func (e fieldSizeError) Error() string {
	return fmt.Sprintf("keepass: %s field size is %d, should be %d", e.name, e.size, e.want)
}
