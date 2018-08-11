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

	log "github.com/sirupsen/logrus"

	"go.mozilla.org/hawk"
)

// an authorization
type authorization struct {
	ID                    string
	Key                   string
	Signers               []string
	HawkTimestampValidity string
	hawkMaxTimestampSkew  time.Duration
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
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
	if a.stats != nil {
		sendStatsErr := a.stats.Timing("hawk.header_parsed", time.Since(getRequestStartTime(r)), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending hawk.header_parsed: %s", sendStatsErr)
		}
	}
	if err != nil {
		return "", false, err
	}
	userid = auth.Credentials.ID
	auth, err = hawk.NewAuthFromRequest(r, a.lookupCred(auth.Credentials.ID), a.lookupNonce)
	if a.stats != nil {
		sendStatsErr := a.stats.Timing("hawk.auth_created", time.Since(getRequestStartTime(r)), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending hawk.auth_created: %s", sendStatsErr)
		}
	}
	if err != nil {
		return "", false, err
	}
	hawk.MaxTimestampSkew = a.auths[userid].hawkMaxTimestampSkew
	err = auth.Valid()
	if a.stats != nil {
		sendStatsErr := a.stats.Timing("hawk.validated", time.Since(getRequestStartTime(r)), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending hawk.validated: %s", sendStatsErr)
		}
		skew := abs(auth.ActualTimestamp.Sub(auth.Timestamp))
		sendStatsErr = a.stats.Timing("hawk.timestamp_skew", skew, nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending hawk.timestamp_skew: %s", sendStatsErr)
		}
	}
	if err != nil {
		return "", false, err
	}
	payloadhash := auth.PayloadHash(r.Header.Get("Content-Type"))
	payloadhash.Write(body)
	if a.stats != nil {
		sendStatsErr := a.stats.Timing("hawk.payload_hashed", time.Since(getRequestStartTime(r)), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending hawk.payload_hashed: %s", sendStatsErr)
		}
	}
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
		return -1, fmt.Errorf("%s is not authorized to sign with key ID %s", userid, keyid)
	}
	return a.signerIndex[tag], nil
}

func (a *autographer) PrintAuthorizations() {
	fmt.Println("\n---- Signers ----")
	for _, signr := range a.signers {
		fmt.Printf("- %s [%s %s]:\n",
			signr.Config().ID, signr.Config().Type, signr.Config().Mode)
		for user, auth := range a.auths {
			for _, authsigner := range auth.Signers {
				if authsigner == signr.Config().ID {
					fmt.Printf("\t* %s\n", user)
				}
			}
		}
	}
	fmt.Println("\n---- Authorizations ----")
	for user, auth := range a.auths {
		fmt.Printf("-%s: \n", user)
		for _, authsigner := range auth.Signers {
			fmt.Printf("\t* %s\n", authsigner)
		}
	}
}
