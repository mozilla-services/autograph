// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestRequestIDWellFormed(t *testing.T) {
	// This method of testing middleware is cribbed from
	// https://stackoverflow.com/questions/51201056/testing-golang-middleware-that-modifies-the-request
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(contextKeyRequestID).(string)
		if uuid.Validate(val) != nil {
			t.Errorf("requestID is not a valid uuid! %v", val)
		}
	})

	handlerToTest := setRequestID()(nextHandler)

	req := httptest.NewRequest("GET", "http://foo.bar/", nil)

	handlerToTest.ServeHTTP(httptest.NewRecorder(), req)
}
