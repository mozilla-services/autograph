// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

// A autographer signs input data with a private key
type autographer struct {
	signers []Signer
}

func (a *autographer) addSigner(signer Signer) {
	a.signers = append(a.signers, signer)
}

// The signature endpoint accepts a list of signature requests in a HAWK authenticated POST request
// and calls the signers to generate signature responses.
func (a *autographer) signature(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts POST only", r.Method)
		return
	}
	if !a.authorized(r.Header.Get("Authorization")) {
		httpError(w, http.StatusUnauthorized, "request is not authorized; provide a valid HAWK authorization")
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}
	var sigreqs []signaturerequest
	err = json.Unmarshal(body, &sigreqs)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to parse request body: %v", err)
		return
	}
	sigresps := make([]signatureresponse, len(sigreqs))
	for i, sigreq := range sigreqs {
		hash, err := getInputHash(sigreq)
		if err != nil {
			httpError(w, http.StatusBadRequest, "%v", err)
			return
		}
		rawsig, err := a.signers[0].sign(hash)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
			return
		}
		sigresps[i].Signatures = append(sigresps[i].Signatures, signaturedata{
			Encoding:  "b64url",
			Signature: rawsig.toBase64Url(),
			Hash:      "sha384",
		})
		sigresps[i].Ref = id()
	}
	respdata, err := json.Marshal(sigresps)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
		return
	}
	log.Printf("signing operation succeeded:%s", respdata)
	w.Write(respdata)
}

// heartbeat returns a simple message indicating that the API is alive and well
func (a *autographer) heartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	w.Write([]byte("ohai"))
}

func (a *autographer) authorized(auth string) bool {
	return true
}
