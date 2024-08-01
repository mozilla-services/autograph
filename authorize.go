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
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"

	"go.mozilla.org/hawk"
)

// an authorization
type authorization struct {
	ID      string
	Key     string
	Signers []string
}

// authIDFormat is a regex for the format Authorization IDs must follow
const authIDFormat = `^[a-zA-Z0-9-_]{1,255}$`

var authIDFormatRegexp = regexp.MustCompile(authIDFormat)

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// authorizeHeader validates the existence of the Authorization header as a hawk
// authorization header and makes sure that it is valid. It does not validate the
// body of the request, that is done within authorizeBody. This function returns
// the hawk auth struct, the userid, and an error which will indicate whether
// validation was successful.
func (a *autographer) authorizeHeader(r *http.Request) (auth *hawk.Auth, userid string, err error) {
	if r.Header.Get("Authorization") == "" {
		return nil, "", fmt.Errorf("missing Authorization header")
	}
	auth, err = hawk.ParseRequestHeader(r.Header.Get("Authorization"))
	sendStatsErr := a.stats.Timing("hawk.header_parsed", time.Since(getRequestStartTime(r)), nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending hawk.header_parsed: %s", sendStatsErr)
	}
	if err != nil {
		return nil, "", err
	}
	userid = auth.Credentials.ID
	auth, err = hawk.NewAuthFromRequest(r, a.lookupCred(userid), a.lookupNonce)
	sendStatsErr = a.stats.Timing("hawk.auth_created", time.Since(getRequestStartTime(r)), nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending hawk.auth_created: %s", sendStatsErr)
	}
	if err != nil {
		return nil, "", err
	}
	_, err = a.getAuthByID(userid)
	if err != nil {
		return nil, "", fmt.Errorf("error finding auth for id %s for hawk.MaxTimestampSkew: %w", userid, err)
	}
	hawk.MaxTimestampSkew = a.hawkMaxTimestampSkew
	err = auth.Valid()
	sendStatsErr = a.stats.Timing("hawk.validated", time.Since(getRequestStartTime(r)), nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending hawk.validated: %s", sendStatsErr)
	}
	skew := abs(auth.ActualTimestamp.Sub(auth.Timestamp))
	sendStatsErr = a.stats.Timing("hawk.timestamp_skew", skew, nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending hawk.timestamp_skew: %s", sendStatsErr)
	}

	if err != nil {
		return nil, "", err
	}
	return auth, userid, nil
}

// authorizeBody validates the body within the request and returns
// an error which will be nil if the authorization is successful
func (a *autographer) authorizeBody(auth *hawk.Auth, r *http.Request, body []byte) (err error) {
	payloadhash := auth.PayloadHash(r.Header.Get("Content-Type"))
	payloadhash.Write(body)
	sendStatsErr := a.stats.Timing("hawk.payload_hashed", time.Since(getRequestStartTime(r)), nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending hawk.payload_hashed: %s", sendStatsErr)
	}
	if !auth.ValidHash(payloadhash) {
		return fmt.Errorf("payload validation failed")
	}
	return nil
}

// authorize combines authorizeHeader and authorizeBody into one function.
func (a *autographer) authorize(r *http.Request, body []byte) (userid string, err error) {
	auth, userid, err := a.authorizeHeader(r)
	if err != nil {
		return userid, err
	}
	err = a.authorizeBody(auth, r, body)
	return userid, err
}

// lookupCred searches the authorizations for a user whose id matches the provided
// id string. If found, a Credential function is return to complete the hawk authorization.
// If not found, a function that returns an error is returned.
func (a *autographer) lookupCred(id string) hawk.CredentialsLookupFunc {
	auth, err := a.getAuthByID(id)
	if err == nil {
		// matching user found, return its token
		return func(creds *hawk.Credentials) error {
			creds.Key = auth.Key
			creds.Hash = sha256.New
			return nil
		}
	}
	// credentials not found or other error, return a function that returns a CredentialError
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
