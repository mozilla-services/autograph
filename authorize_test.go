// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"go.mozilla.org/hawk"

	"go.mozilla.org/autograph/formats"
)

func TestMissingAuthorization(t *testing.T) {
	t.Parallel()

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ag.authorizeHeader(req)
	if err == nil {
		t.Errorf("expected auth to fail with missing authorization but succeeded")
	}
	if err.Error() != "missing Authorization header" {
		t.Errorf("expected auth to fail with missing authorization but got error: %v", err)
	}
}

func TestBogusAuthorization(t *testing.T) {
	t.Parallel()

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", `Hawk thisisbob="bob", andhereisamac="nVg5STp2fD+P7G3ELmUztb3hP/LQajwD+FDQM7rZvhw=", ts="1453681057"`)
	_, _, err = ag.authorizeHeader(req)
	if err == nil {
		t.Errorf("expected auth to fail with invalid authorization but succeeded")
	}
	if err.Error() != "hawk: invalid mac, missing or empty" {
		t.Errorf("expected auth to fail with no authorization but got error: %v", err)
	}
}

func TestBadPayload(t *testing.T) {
	t.Parallel()

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	authheader := getAuthHeader(req, ag.auths[conf.Authorizations[0].ID].ID, ag.auths[conf.Authorizations[0].ID].Key, sha256.New, id(), "application/json", []byte(`9247oldfjd18weohfa`))
	req.Header.Set("Authorization", authheader)
	_, err = ag.authorize(req, body)
	if err == nil {
		t.Errorf("expected auth to fail with payload validation failed but succeeded")
	}
	if err.Error() != "payload validation failed" {
		t.Errorf("expected auth to fail with payload validation failed but got error: %v", err)
	}
}

func TestExpiredAuth(t *testing.T) {
	t.Parallel()

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", `Hawk id="bob", mac="nVg5STp2fD+P7G3ELmUztb3hP/LQajwD+FDQM7rZvhw=", ts="1453681057", nonce="TKLzwtGS", hash="sL12YYG2CnALd5o5dqHRKjNO0AvgmPPeIqlfZQfszfo=", ext="59d2rtbmji6617pthvwa1h370"`)
	_, _, err = ag.authorizeHeader(req)
	if err == nil {
		t.Errorf("expected auth to fail with expired timestamp but succeeded")
	}
	if err.Error() != hawk.ErrTimestampSkew.Error() {
		t.Errorf("expected auth to fail with expired timestamp but got error: %v", err)
	}
}

func TestDuplicateNonce(t *testing.T) {
	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, ag.auths[conf.Authorizations[0].ID].ID, ag.auths[conf.Authorizations[0].ID].Key, sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	// run it once
	_, _, err = ag.authorizeHeader(req)
	// and run it twice
	_, _, err = ag.authorizeHeader(req)
	if err == nil {
		t.Errorf("expected auth to fail with duplicate nonce, but succeeded")
	}
	if err.Error() != hawk.ErrReplay.Error() {
		t.Errorf("expected auth to fail with duplicate nonces but got error: %v", err)
	}

}

func TestNonceFromLRU(t *testing.T) {
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", nil)
	if err != nil {
		t.Fatal(err)
	}

	auth1 := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   ag.auths[conf.Authorizations[0].ID].ID,
			Key:  ag.auths[conf.Authorizations[0].ID].Key,
			Hash: sha256.New},
		0)
	req.Header.Set("Authorization", auth1.RequestHeader())
	_, _, err = ag.authorizeHeader(req)
	if err != nil {
		t.Fatalf("error authorizing header for first request: %s", err)
	}

	auth2 := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   ag.auths[conf.Authorizations[0].ID].ID,
			Key:  ag.auths[conf.Authorizations[0].ID].Key,
			Hash: sha256.New},
		0)
	req.Header.Set("Authorization", auth2.RequestHeader())
	_, _, err = ag.authorizeHeader(req)
	if err != nil {
		t.Fatalf("error authorizing header for second request: %s", err)
	}

	if ag.nonces.Contains(auth1.Nonce) {
		t.Errorf("First nonce %q found in cache, should have been removed", auth1.Nonce)
		t.Logf("nonces: %+v", ag.nonces.Keys())
	}
	if !ag.nonces.Contains(auth2.Nonce) {
		t.Errorf("Second nonce %q not found in cache, should have been present", auth2.Nonce)
		t.Logf("nonces: %+v", ag.nonces.Keys())
	}
}

func TestSignerNotFound(t *testing.T) {
	t.Parallel()

	pos, err := ag.getSignerID(`unknown018qoegdxc`, `unkown093ytid`)
	if err == nil || pos != -1 {
		t.Errorf("expected to fail lookup up a signer but succeeded")
	}
}

func TestDefaultSignerNotFound(t *testing.T) {
	t.Parallel()

	pos, err := ag.getSignerID(`unknown018qoegdxc`, ``)
	if err == nil || pos != -1 {
		t.Errorf("expected to fail lookup up a signer but succeeded")
	}
}

// Two authorizations sharing the same ID should fail
func TestAddDuplicateAuthorization(t *testing.T) {
	t.Parallel()

	var authorizations = []formats.Authorization{
		{
			ID: "alice",
		},
		{
			ID: "alice",
		},
	}
	defer func() {
		if e := recover(); e != nil {
			if e != `authorization id 'alice' already defined, duplicates are not permitted` {
				t.Fatalf("expected authorization loading to fail with duplicate error but got: %v", e)
			}
		}
	}()
	tmpag := newAutographer(1)
	tmpag.addSigners(conf.Signers)
	tmpag.addAuthorizations(authorizations)
}

// set an authorization with a ts validity of 2 seconds, then sleep 5 seconds
// to trigger the hawk skew error
func TestHawkTimestampSkewFail(t *testing.T) {
	t.Parallel()

	tmpag := newAutographer(1)
	tmpag.addSigners(conf.Signers)
	tmpag.addAuthorizations([]formats.Authorization{
		{
			ID:                    "alice",
			Key:                   "1862300e9bd18eafab2eb8d6",
			HawkTimestampValidity: 2 * time.Second,
			Signers:               []string{"appkey1"},
		}})

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, "alice", "1862300e9bd18eafab2eb8d6", sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	time.Sleep(5 * time.Second)
	_, _, err = tmpag.authorizeHeader(req)
	if err.Error() != hawk.ErrTimestampSkew.Error() {
		t.Errorf("expected auth to fail with skewed timestamp but got error: %v", err)
	}

}
