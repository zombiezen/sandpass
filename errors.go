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
	"errors"
	"net/http"
	"strings"
)

func isUserError(e error) bool {
	return userErrorMessage(e) != ""
}

func userErrorMessage(e error) string {
	ue, ok := e.(interface {
		UserError() string
	})
	if !ok {
		return ""
	}
	return ue.UserError()
}

func errorStatusCode(e error) int {
	sc, ok := e.(interface {
		StatusCode() int
	})
	if !ok {
		return 500
	}
	return sc.StatusCode()
}

func errorRedirect(e error) (code int, u string) {
	r, ok := e.(interface {
		RedirectURL() string
		StatusCode() int
	})
	if !ok {
		return 0, ""
	}
	return r.StatusCode(), r.RedirectURL()
}

type userError struct {
	msg string
	err error
}

func (ue userError) Error() string {
	return ue.err.Error()
}

func (ue userError) UserError() string {
	return ue.msg
}

type xsrfError struct {
	err error
}

func (xe xsrfError) Error() string {
	return "check xsrf: " + xe.err.Error()
}

func (xe xsrfError) UserError() string {
	return "invalid XSRF token"
}

func (xe xsrfError) StatusCode() int {
	return http.StatusBadRequest
}

type notFoundError struct{}

func (notFoundError) Error() string {
	return "not found"
}

func (notFoundError) UserError() string {
	return "404 page not found"
}

func (notFoundError) StatusCode() int {
	return http.StatusNotFound
}

type invalidParentError struct {
	val string
}

func (e invalidParentError) Error() string {
	return "invalid parent " + e.val
}

func (e invalidParentError) UserError() string {
	return e.Error()
}

func (e invalidParentError) StatusCode() int {
	return http.StatusNotFound
}

type rootRedirectError struct {
	err error
}

var errInvalidSession = rootRedirectError{
	err: userError{
		msg: "Invalid session. Please enter your credentials again.",
		err: errors.New("invalid session"),
	},
}

func (e rootRedirectError) Error() string {
	return e.err.Error()
}

func (e rootRedirectError) UserError() string {
	msg := userErrorMessage(e.err)
	if msg == "" {
		return strings.Title(e.err.Error())
	}
	return msg
}

func (e rootRedirectError) StatusCode() int {
	return http.StatusSeeOther
}

func (e rootRedirectError) RedirectURL() string {
	u, _ := router.Get("root").URL()
	q := u.Query()
	q.Set("error", e.UserError())
	u.RawQuery = q.Encode()
	return u.String()
}
