// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
)

func httpError(w http.ResponseWriter, r *http.Request, errorCode int, errorMessage string, args ...interface{}) {
	rid := getRequestID(r)
	log.WithFields(log.Fields{
		"code": errorCode,
		"rid":  rid,
	}).Errorf(errorMessage, args...)
	msg := fmt.Sprintf(errorMessage, args...)
	msg += "\r\nrequest-id: " + rid
	http.Error(w, msg, errorCode)
	return
}
