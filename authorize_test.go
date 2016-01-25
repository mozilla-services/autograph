// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/mozilla-services/hawk-go"
)

func TestMissingAuthorization(t *testing.T) {
	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/signature", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	_, authorize, err := ag.authorize(req, body)
	if authorize {
		t.Errorf("expected auth to fail with missing authorization but succeeded")
	}
	if err.Error() != "missing Authorization header" {
		t.Errorf("expected auth to fail with missing authorization but got error: %v", err)
	}
}

func TestBogusAuthorization(t *testing.T) {
	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/signature", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", `Hawk thisisbob="bob", andhereisamac="nVg5STp2fD+P7G3ELmUztb3hP/LQajwD+FDQM7rZvhw=", ts="1453681057"`)
	_, authorize, err := ag.authorize(req, body)
	if authorize {
		t.Errorf("expected auth to fail with invalid authorization but succeeded")
	}
	if err.Error() != "hawk: invalid mac, missing or empty" {
		t.Errorf("expected auth to fail with no authorization but got error: %v", err)
	}
}

func TestExpiredAuth(t *testing.T) {
	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/signature", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", `Hawk id="tester", mac="nVg5STp2fD+P7G3ELmUztb3hP/LQajwD+FDQM7rZvhw=", ts="1453681057", nonce="TKLzwtGS", hash="sL12YYG2CnALd5o5dqHRKjNO0AvgmPPeIqlfZQfszfo=", ext="59d2rtbmji6617pthvwa1h370"`)
	_, authorize, err := ag.authorize(req, body)
	if authorize {
		t.Errorf("expected auth to fail with expired timestamp but succeeded")
	}
	if err.Error() != fmt.Sprintf("authorization header is older than %s", maxauthage.String()) {
		t.Errorf("expected auth to fail with expired timestamp but got error: %v", err)
	}
}

func TestDuplicateNonce(t *testing.T) {
	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/signature", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, ag.signers[0].AuthorizedUsers[0], ag.signers[0].HawkToken, sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	// run it once
	_, authorize, err := ag.authorize(req, body)
	// and run it twice
	_, authorize, err = ag.authorize(req, body)
	if authorize {
		t.Errorf("expected auth to fail with duplicate nonce, but succeeded")
	}
	if err.Error() != hawk.ErrReplay.Error() {
		t.Errorf("expected auth to fail with duplicate nonces but got error: %v", err)
	}

}

func TestRemoveExpiredNonce(t *testing.T) {
	ag.nonces = make([]nonce, 0)
	ag.nonces = append(ag.nonces, nonce{value: "shouldexpire", timestamp: time.Now().Add(-2 * maxauthage)})
	ag.nonces = append(ag.nonces, nonce{value: "iscurrent", timestamp: time.Now()})
	ag.removeNonces()
	if len(ag.nonces) != 1 {
		t.Errorf("found %d nonces when only one was expected", len(ag.nonces))
	}
	for _, nonce := range ag.nonces {
		if nonce.value == "shouldexpire" {
			t.Errorf("found nonce `shouldexpire` which should have been expired")
		}
	}
}
