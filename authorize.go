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

	"github.com/mozilla-services/hawk-go"
)

const maxauthage time.Duration = 60 * time.Second

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
		return
	}
	if time.Now().Sub(auth.Timestamp) > maxauthage {
		return "", false, fmt.Errorf("authorization header is older than %s", maxauthage.String())
	}
	userid = auth.Credentials.ID
	auth, err = hawk.NewAuthFromRequest(r, a.lookupCred(auth.Credentials.ID), a.lookupNonce)
	if err != nil {
		return
	}
	err = auth.Valid()
	if err != nil {
		return
	}
	payloadhash := auth.PayloadHash(r.Header.Get("Content-Type"))
	payloadhash.Write(body)
	if !auth.ValidHash(payloadhash) {
		err = fmt.Errorf("payload validation failed")
		return
	}
	authorize = true
	return
}

func (a *autographer) lookupCred(id string) hawk.CredentialsLookupFunc {
	for _, signer := range a.signers {
		for _, autheduser := range signer.AuthorizedUsers {
			if autheduser == id {
				// matching user found, return its token
				return func(creds *hawk.Credentials) error {
					creds.Key = signer.HawkToken
					creds.Hash = sha256.New
					return nil
				}
			}
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

type nonce struct {
	value     string
	timestamp time.Time
}

func (a *autographer) lookupNonce(val string, ts time.Time, creds *hawk.Credentials) bool {
	for _, n := range a.nonces {
		if val == n.value {
			return false
		}
	}
	a.noncesLock.Lock()
	a.nonces = append(a.nonces, nonce{value: val, timestamp: time.Now()})
	a.noncesLock.Unlock()
	return true
}

func (a *autographer) removeNonces() {
	now := time.Now()
	for i, n := range a.nonces {
		if now.Sub(n.timestamp) > maxauthage {
			// the nonce is too old, delete it
			a.noncesLock.Lock()
			a.nonces = append(a.nonces[:i], a.nonces[i+1:]...)
			a.noncesLock.Unlock()
		}
	}
}

// getSignerId returns the signer identifier for the user. If a keyid is specified,
// the corresponding signer is returned. If no signer is found, an error is returned.
func (a *autographer) getSignerID(userid, keyid string) (signerID int, err error) {
	return 0, nil
}
