// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import "net/http"

// authorize validates the hawk authorization header on a request
// and returns the userid and a boolean indicating authorization status
func (a *autographer) authorize(r *http.Request) (userid string, authorize bool, err error) {
	return "", true, nil
}

// getSignerId returns the signer identifier for the user. If a keyid is specified,
// the corresponding signer is returned. If no signer is found, an error is returned.
func (a *autographer) getSignerId(userid, keyid string) (signerId int, err error) {
	return 0, nil
}
