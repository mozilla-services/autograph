// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"go.mozilla.org/hawk"
)

// an authorization
type authorization struct {
	ID      string
	Key     string
	Signers []string
}

// authorize validates the hawk authorization header on a request
// and returns the userid and a boolean indicating authorization status
func (a *autographer) authorize(r *http.Request, body []byte) (userid string, authorize bool, err error) {
	var (
		auth *hawk.Auth
	)
	if r.Header.Get("Authorization") == "" {
		return "", false, fmt.Errorf("missing Authorization header")
	}
	auth, err = hawk.ParseRequestHeader(r.Header.Get("Authorization"))
	if err != nil {
		return "", false, err
	}
	userid = auth.Credentials.ID
	auth, err = hawk.NewAuthFromRequest(r, a.lookupCred(auth.Credentials.ID), a.lookupNonce)
	if err != nil {
		return "", false, err
	}
	err = auth.Valid()
	if err != nil {
		return "", false, err
	}
	payloadhash := auth.PayloadHash(r.Header.Get("Content-Type"))
	payloadhash.Write(body)
	if !auth.ValidHash(payloadhash) {
		return "", false, fmt.Errorf("payload validation failed")
	}
	return userid, true, nil
}

// lookupCred searches the authorizations for a user whose id matches the provided
// id string. If found, a Credential function is return to complete the hawk authorization.
// If not found, a function that returns an error is returned.
func (a *autographer) lookupCred(id string) hawk.CredentialsLookupFunc {
	if _, ok := a.auths[id]; ok {
		// matching user found, return its token
		return func(creds *hawk.Credentials) error {
			creds.Key = a.auths[id].Key
			creds.Hash = sha256.New
			return nil
		}
	}
	// credentials not found, return a function that returns a CredentialError
	return func(creds *hawk.Credentials) error {
		return &hawk.CredentialError{
			Type: hawk.UnknownID,
			Credentials: &hawk.Credentials{
				ID:   id,
				Key:  "-",
				Hash: sha256.New,
			},
		}
	}
}

// lookupNonce searches the LRU cache for a previous nonce that matches the value provided in
// val. If found, this is a replay attack, and `false` is returned.
func (a *autographer) lookupNonce(val string, ts time.Time, creds *hawk.Credentials) bool {
	if a.nonces.Contains(val) {
		return false
	}
	a.nonces.Add(val, time.Now())
	return true
}

// getSignerId returns the signer identifier for the user. If a keyid is specified,
// the corresponding signer is returned. If no signer is found, an error is returned
// and the signer identifier is set to -1.
func (a *autographer) getSignerID(userid, keyid string) (int, error) {
	tag := userid + "+" + keyid
	if _, ok := a.signerIndex[tag]; !ok {
		if keyid == "" {
			return -1, fmt.Errorf("%q does not have a default signing key", userid)
		}
		return -1, fmt.Errorf("%q is not authorized to sign with key ID %q", userid, keyid)
	}
	return a.signerIndex[tag], nil
}
