// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// ErrAuthNotFound is for when autographer.getAuthByID doesn't find an auth
var ErrAuthNotFound = fmt.Errorf("authorization not found")

func httpError(w http.ResponseWriter, r *http.Request, errorCode int, errorMessage string, args ...interface{}) {
	rid := getRequestID(r)
	log.WithFields(log.Fields{
		"code": errorCode,
		"rid":  rid,
	}).Errorf(errorMessage, args...)
	msg := fmt.Sprintf(errorMessage, args...)
	msg += "\r\nrequest-id: " + rid
	// when nginx is in front of go, nginx requires that the entire
	// request body is read before writing a response.
	// https://github.com/golang/go/issues/15789
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
	http.Error(w, msg, errorCode)
	return
}
