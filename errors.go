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
	"errors"
	"net/http"
	"net/url"
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
	return "/?error=" + url.QueryEscape(e.UserError())
}
