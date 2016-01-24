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
	nonces  []nonce
}

func (a *autographer) addSigner(signer Signer) {
	a.signers = append(a.signers, signer)
}

// handleSignature endpoint accepts a list of signature requests in a HAWK authenticated POST request
// and calls the signers to generate signature responses.
func (a *autographer) handleSignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts POST only", r.Method)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}
	userid, authorized, err := a.authorize(r, body)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "authorization verification failed: %v", err)
		return
	}
	if !authorized {
		httpError(w, http.StatusUnauthorized, "request is not authorized; provide a valid HAWK authorization")
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
		signerID, err := a.getSignerID(userid, sigreq.KeyID)
		if err != nil || (signerID > (len(a.signers) - 1)) {
			httpError(w, http.StatusInternalServerError, "no valid signer found for userid %q", userid)
			return
		}
		rawsig, err := a.signers[signerID].sign(hash)
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
	w.WriteHeader(http.StatusCreated)
	w.Write(respdata)
}

// handleHeartbeat returns a simple message indicating that the API is alive and well
func (a *autographer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	w.Write([]byte("ohai"))
}
