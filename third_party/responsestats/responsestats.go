// Copyright (c) 2013, Ross Light
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions
// and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
// and the following disclaimer in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
// IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package responsestats

import "net/http"

// ResponseStats is a ResponseWriter that records statistics about a response.
type ResponseStats struct {
	w    http.ResponseWriter
	code int
	size int64
}

// New returns a new ResponseStats that writes to w.
func New(w http.ResponseWriter) *ResponseStats {
	return &ResponseStats{w: w}
}

// StatusCode returns the status code sent with WriteHeader or 0 if WriteHeader has not been called.
func (r *ResponseStats) StatusCode() int {
	return r.code
}

// Size returns the number of bytes written to the underlying ResponseWriter.
func (r *ResponseStats) Size() int64 {
	return r.size
}

func (r *ResponseStats) Header() http.Header {
	return r.w.Header()
}

func (r *ResponseStats) WriteHeader(statusCode int) {
	r.w.WriteHeader(statusCode)
	r.code = statusCode
}

func (r *ResponseStats) Write(p []byte) (n int, err error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	n, err = r.w.Write(p)
	r.size += int64(n)
	return
}
