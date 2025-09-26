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
)

func TestMissingAuthorization(t *testing.T) {
	ag, _ := newTestAutographer(t)

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
	ag, _ := newTestAutographer(t)

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
	ag, conf := newTestAutographer(t)

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := ag.getAuthByID(conf.Authorizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	authheader := getAuthHeader(req, auth.ID, auth.Key, sha256.New, id(), "application/json", []byte(`9247oldfjd18weohfa`))
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
	ag, _ := newTestAutographer(t)

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
	ag, conf := newTestAutographer(t)

	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bodyrdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", bodyrdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth, err := ag.getAuthByID(conf.Authorizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	authheader := getAuthHeader(req, auth.ID, auth.Key, sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	// run it once
	_, _, _ = ag.authorizeHeader(req)
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
	ag, conf := newTestAutographer(t)

	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", nil)
	if err != nil {
		t.Fatal(err)
	}

	authCreds, err := ag.getAuthByID(conf.Authorizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	auth1 := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   authCreds.ID,
			Key:  authCreds.Key,
			Hash: sha256.New},
		0)
	req.Header.Set("Authorization", auth1.RequestHeader())
	_, _, err = ag.authorizeHeader(req)
	if err != nil {
		t.Fatalf("error authorizing header for first request: %s", err)
	}

	auth2 := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   authCreds.ID,
			Key:  authCreds.Key,
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
	ag, _ := newTestAutographer(t)

	_, err := ag.authBackend.getSignerForUser(`unknown018qoegdxc`, `unkown093ytid`)
	if err == nil {
		t.Errorf("expected to fail lookup up a signer but succeeded")
	}
}

func TestDefaultSignerNotFound(t *testing.T) {
	ag, _ := newTestAutographer(t)

	_, err := ag.authBackend.getSignerForUser(`unknown018qoegdxc`, ``)
	if err == nil {
		t.Errorf("expected to fail lookup up a signer but succeeded")
	}
}

func TestAutographerAddAuthorizationsFails(t *testing.T) {
	ag, _ := newTestAutographer(t)

	testcases := []struct {
		name   string
		auths  []authorization
		errStr string
	}{
		{
			name: "two authorizations with same ID fails",
			auths: []authorization{
				{
					ID:      "alice",
					Signers: []string{"appkey1"},
				},
				{
					ID:      "alice",
					Signers: []string{"appkey2"},
				},
			},
			errStr: `authorization id 'alice' already defined, duplicates are not permitted`,
		},
		{
			name: "authorization without a signer ID fails",
			auths: []authorization{
				{
					ID:      "bernie",
					Signers: []string{},
				},
			},
			errStr: `auth id "bernie" must have at least one signer configured`,
		},
		{
			name: "invalid empty string auth ID fails",
			auths: []authorization{
				{
					ID:      "",
					Signers: []string{"appkey1"},
				},
			},
			errStr: `authorization id '' is invalid, it must match ^[a-zA-Z0-9-_]{1,255}$`,
		},
		{
			name: "invalid long auth ID fails",
			auths: []authorization{
				{
					ID:      "fe3b321f83bf7a09c9199d118915f74ffef8de9b7abcc2dae93ea83cf0541a0c127bc91d1a0ba028af781553abad2bb4101ea1f84559e395d6f301308b4ead9956ef4ccd1ea7c8ce50a422cc78e7ddc1518ef8e54a08141e277808638b4104acf3e6211189222feea199c7da25d9aff5b55c02f6f686f2f1e91ea97dda6b33135593c5c4f80106d5836646557e2b001b3c531d10a4e9f6b7a6b4bd99303bce40592e13d1a8daad93f5cfd2fa78f423ae3dcad40303a0d9d85a166142e09f507904fee326470d1d50af28e2f4348f307d2f76b9c5dd3f9f9b3537c7ef86e63b606b1c57b408c8ae687e7d5c969002203777240029d4998644dbc347fc8f666c5b",
					Signers: []string{"appkey1"},
				},
			},
			errStr: `authorization id 'fe3b321f83bf7a09c9199d118915f74ffef8de9b7abcc2dae93ea83cf0541a0c127bc91d1a0ba028af781553abad2bb4101ea1f84559e395d6f301308b4ead9956ef4ccd1ea7c8ce50a422cc78e7ddc1518ef8e54a08141e277808638b4104acf3e6211189222feea199c7da25d9aff5b55c02f6f686f2f1e91ea97dda6b33135593c5c4f80106d5836646557e2b001b3c531d10a4e9f6b7a6b4bd99303bce40592e13d1a8daad93f5cfd2fa78f423ae3dcad40303a0d9d85a166142e09f507904fee326470d1d50af28e2f4348f307d2f76b9c5dd3f9f9b3537c7ef86e63b606b1c57b408c8ae687e7d5c969002203777240029d4998644dbc347fc8f666c5b' is invalid, it must match ^[a-zA-Z0-9-_]{1,255}$`,
		},
		{
			name: "invalid auth ID with symbols fails",
			auths: []authorization{
				{
					ID:      "%!@",
					Signers: []string{"appkey1"},
				},
			},
			errStr: `authorization id '%!@' is invalid, it must match ^[a-zA-Z0-9-_]{1,255}$`,
		},
		{
			name: "invalid auth ID with newline fails",
			auths: []authorization{
				{
					ID:      "\n",
					Signers: []string{"appkey1"},
				},
			},
			errStr: `authorization id '
' is invalid, it must match ^[a-zA-Z0-9-_]{1,255}$`,
		},
		{
			name: "invalid auth ID with period fails",
			auths: []authorization{
				{
					ID:      ".",
					Signers: []string{"appkey1"},
				},
			},
			errStr: `authorization id '.' is invalid, it must match ^[a-zA-Z0-9-_]{1,255}$`,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			err := ag.addAuthorizations(testcase.auths)
			if err == nil {
				t.Fatalf("%s: addAuthorizations did not fail as expected", testcase.name)
			}
			if err.Error() != testcase.errStr {
				t.Fatalf("%s: addAuthorizations failed with %q instead of expected error %q", testcase.name, err.Error(), testcase.errStr)
			}
		})
	}
}

// set an authorization with a ts validity of 2 seconds, then sleep 5 seconds
// to trigger the hawk skew error
func TestHawkTimestampSkewFail(t *testing.T) {
	ag, _ := newTestAutographer(t)

	var err error
	ag.hawkMaxTimestampSkew, err = time.ParseDuration("2s")
	if err != nil {
		t.Fatal(err)
	}
	_ = ag.addAuthorizations([]authorization{

		{
			ID:      "alice",
			Key:     "1862300e9bd18eafab2eb8d6",
			Signers: []string{"appkey1"},
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
	_, _, err = ag.authorizeHeader(req)
	if err.Error() != hawk.ErrTimestampSkew.Error() {
		t.Errorf("expected auth to fail with skewed timestamp but got error: %v", err)
	}

}
