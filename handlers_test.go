// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/hawk"
)

func TestSignaturePass(t *testing.T) {
	var TESTCASES = []struct {
		endpoint   string
		signatures []signaturerequest
	}{
		{
			// Sign data with Content-Signature
			"/sign/data",
			[]signaturerequest{
				// request signature that need to prepend the content-signature:\x00 header
				signaturerequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: "appkey2",
				},
				// request signature that will use the default hash function
				signaturerequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: "appkey3",
				},
				// request signature of raw data that already has the content-signature header prepended
				signaturerequest{
					Input: "Q29udGVudC1TaWduYXR1cmU6ADwhRE9DVFlQRSBIVE1MPgo8aHRtbD4KPCEtLSBodHRwczovL2J1Z3ppbGxhLm1vemlsbGEub3JnL3Nob3dfYnVnLmNnaT9pZD0xMjI2OTI4IC0tPgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPHRpdGxlPlRlc3RwYWdlIGZvciBidWcgMTIyNjkyODwvdGl0bGU+CjwvaGVhZD4KPGJvZHk+CiAgSnVzdCBhIGZ1bGx5IGdvb2QgdGVzdHBhZ2UgZm9yIEJ1ZyAxMjI2OTI4PGJyLz4KPC9ib2R5Pgo8L2h0bWw+Cg==",
					KeyID: "appkey1",
				},
			},
		},
		{
			// Sign hash with Content Signature
			"/sign/hash",
			[]signaturerequest{
				// request signature of a precomputed sha384 hash
				signaturerequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
				},
			},
		},
		{
			// Sign a regular add-on
			"/sign/data",
			[]signaturerequest{
				// request signature that need to prepend the content-signature:\x00 header
				signaturerequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: "webextensions-rsa",
				},
			},
		},
		{
			// Sign an extension
			"/sign/data",
			[]signaturerequest{
				// request signature that need to prepend the content-signature:\x00 header
				signaturerequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: "extensions-ecdsa",
				},
			},
		},
	}
	for i, testcase := range TESTCASES {
		delete(sr.entry, "-")
		userid := conf.Authorizations[0].ID
		body, err := json.Marshal(testcase.signatures)
		if err != nil {
			t.Fatal(err)
		}
		rdr := bytes.NewReader(body)
		req, err := http.NewRequest("POST", "http://foo.bar"+testcase.endpoint, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, ag.auths[userid].ID, ag.auths[userid].Key,
			sha256.New, id(), "application/json", body)
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusCreated || w.Body.String() == "" {
			t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
		}
		// verify that we got a proper signature response, with a valid signature
		var responses []signatureresponse
		err = json.Unmarshal(w.Body.Bytes(), &responses)
		if err != nil {
			t.Fatal(err)
		}
		if len(responses) != len(testcase.signatures) {
			t.Fatalf("in test case %d, failed to receive as many responses (%d) as we sent requests (%d)",
				i, len(responses), len(testcase.signatures))
		}
		for j, response := range responses {
			t.Logf("test case %d on endpoint %q in response %d", i, testcase.endpoint, j)
			if !verifyContentSignature(t, testcase.signatures[j].Input, response, testcase.endpoint) {
				t.Fatalf("in test case %d on endpoint %q, signature verification failed in response %d; request was: %+v",
					i, testcase.endpoint, j, req)
			}
		}
	}
}

func TestSignatureFail(t *testing.T) {
	var TESTCASES = []struct {
		endpoint string
		method   string
		body     string
	}{
		// missing request body
		{`/sign/data`, `POST`, ``},
		{`/sign/hash`, `POST`, ``},
		// bad hashwith algorithm
		{`/sign/data`, `POST`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// hashwith and template parameters are forbidden on this endpoint
		{`/sign/hash`, `POST`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		{`/sign/hash`, `POST`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// no GET, PUT or HEAD requests on these endpoints
		{`/sign/data`, `GET`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		{`/sign/data`, `PUT`, ``},
		{`/sign/data`, `HEAD`, ``},
		{`/sign/hash`, `GET`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		{`/sign/hash`, `PUT`, ``},
		{`/sign/hash`, `HEAD`, ``},
	}
	for i, testcase := range TESTCASES {
		delete(sr.entry, "-")
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest(testcase.method, "http://foo.bar"+testcase.endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, ag.auths[conf.Authorizations[0].ID].ID, ag.auths[conf.Authorizations[0].ID].Key, sha256.New, id(), "application/json", []byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code == http.StatusCreated {
			t.Fatalf("test case %d failed with %d: %s", i, w.Code, w.Body.String())
		}
	}
}

func TestAuthFail(t *testing.T) {
	var TESTCASES = []struct {
		user        string
		token       string
		hash        func() hash.Hash
		contenttype string
		body        string
	}{
		// test bad user
		{`baduser`, `fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu`, sha256.New, `application/json`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// test bad token
		{`tester`, `badtoken`, sha256.New, `application/json`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// test wrong hash
		{`tester`, `fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu`, sha512.New, `application/json`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// test wrong content type
		{`tester`, `fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu`, sha256.New, `test/plain`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// test missing payload
		{`tester`, `fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu`, sha256.New, `application/json`, ``},
	}
	for i, testcase := range TESTCASES {
		delete(sr.entry, "-")
		body := strings.NewReader(`[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`)
		req, err := http.NewRequest("POST", "http://foo.bar/sign/data", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, testcase.user, testcase.token, testcase.hash, id(), testcase.contenttype, []byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		t.Log(i, authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("test case %d was authorized with %d and should have failed; authorization header was: %s; response was: %s",
				i, w.Code, req.Header.Get("Authorization"), w.Body.String())
		}
	}
}

func TestContentSignatureInResponse(t *testing.T) {
	var TESTCASES = []struct {
		expect   bool
		endpoint string
		body     string
	}{
		{true, `/sign/data`, `[{"template": "content-signature", "hashwith": "sha384", "input":"PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNo"}]`},
		{true, `/sign/hash`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		{false, `/sign/data`, `[{"hashwith": "sha384", "input":"PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNo"}]`},
	}
	for i, testcase := range TESTCASES {
		delete(sr.entry, "-")
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest("POST", "http://foo.bar"+testcase.endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, ag.auths[conf.Authorizations[0].ID].ID, ag.auths[conf.Authorizations[0].ID].Key, sha256.New, id(), "application/json", []byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("test case %d failed with %d: %s", i, w.Code, w.Body.String())
		}
		var responses []signatureresponse
		err = json.Unmarshal(w.Body.Bytes(), &responses)
		if err != nil {
			t.Fatal(err)
		}
		for j, response := range responses {
			if testcase.expect && response.Signature == "" {
				t.Fatalf("in test case %d response %d on endpoint %q, expected to find content-signature but didn't; request was %+v",
					i, j, testcase.endpoint, req)
			}
			if !testcase.expect && response.Signature != "" {
				t.Fatalf("in test case %d response %d on endpoint %q, expected to not find content-signature but did; request was %+v",
					i, j, testcase.endpoint, req)
			}
		}
	}
}
func TestHeartbeat(t *testing.T) {
	var TESTCASES = []struct {
		expect int
		method string
	}{
		{http.StatusOK, `GET`},
		{http.StatusMethodNotAllowed, `POST`},
		{http.StatusMethodNotAllowed, `PUT`},
		{http.StatusMethodNotAllowed, `HEAD`},
	}
	for i, testcase := range TESTCASES {
		req, err := http.NewRequest(testcase.method, "http://foo.bar/__heartbeat__", nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handleHeartbeat(w, req)
		if w.Code != testcase.expect {
			t.Fatalf("test case %d failed with code %d but %d was expected",
				i, w.Code, testcase.expect)
		}
	}
}

func TestVersion(t *testing.T) {
	var TESTCASES = []struct {
		expect int
		method string
	}{
		{http.StatusOK, `GET`},
		{http.StatusMethodNotAllowed, `POST`},
		{http.StatusMethodNotAllowed, `PUT`},
		{http.StatusMethodNotAllowed, `HEAD`},
	}
	for i, testcase := range TESTCASES {
		req, err := http.NewRequest(testcase.method, "http://foo.bar/__version__", nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handleVersion(w, req)
		if w.Code != testcase.expect {
			t.Fatalf("test case %d failed with code %d but %d was expected",
				i, w.Code, testcase.expect)
		}
	}
}

// An authorization without at least one signer configured should not have
// a default signer configured in the signerIndex
func TestAuthWithoutSigner(t *testing.T) {
	var authorizations = []authorization{
		authorization{
			ID: "alice",
		},
	}
	tmpag := newAutographer(1)
	tmpag.addSigners(conf.Signers)
	tmpag.addAuthorizations(authorizations)
	tmpag.makeSignerIndex()
	if _, ok := tmpag.signerIndex[authorizations[0].ID+"+"]; ok {
		t.Fatalf("found a default signer but shouldn't have")
	}
}

// verify that user `alice` and `bob` are allowed to sign
// with their respective keys:
// * `appkey1` and `appkey2` for `alice`
// * `appkey2` only for `bob`
func TestSignerAuthorized(t *testing.T) {
	var TESTCASES = []struct {
		userid string
		sgs    []signaturerequest
	}{
		{
			userid: conf.Authorizations[0].ID,
			sgs: []signaturerequest{
				signaturerequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: conf.Authorizations[0].Signers[0],
				},
				signaturerequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
					KeyID: conf.Authorizations[0].Signers[0],
				},
				signaturerequest{
					Input: "Q29udGVudC1TaWduYXR1cmU6ADwhRE9DVFlQRSBIVE1MPgo8aHRtbD4KPCEtLSBodHRwczovL2J1Z3ppbGxhLm1vemlsbGEub3JnL3Nob3dfYnVnLmNnaT9pZD0xMjI2OTI4IC0tPgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPHRpdGxlPlRlc3RwYWdlIGZvciBidWcgMTIyNjkyODwvdGl0bGU+CjwvaGVhZD4KPGJvZHk+CiAgSnVzdCBhIGZ1bGx5IGdvb2QgdGVzdHBhZ2UgZm9yIEJ1ZyAxMjI2OTI4PGJyLz4KPC9ib2R5Pgo8L2h0bWw+Cg==",
					KeyID: conf.Authorizations[0].Signers[1],
				},
			},
		},
		{
			userid: conf.Authorizations[1].ID,
			sgs: []signaturerequest{
				signaturerequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: conf.Authorizations[1].Signers[0],
				},
				signaturerequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
					KeyID: conf.Authorizations[1].Signers[0],
				},
			},
		},
	}
	for tid, testcase := range TESTCASES {
		delete(sr.entry, "-")
		userid := testcase.userid
		body, err := json.Marshal(testcase.sgs)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s", body)
		rdr := bytes.NewReader(body)
		req, err := http.NewRequest("POST", "http://foo.bar/sign/data", rdr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%+v\n", sr.entry["-"])
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, ag.auths[userid].ID, ag.auths[userid].Key,
			sha256.New, id(), "application/json", body)
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusCreated || w.Body.String() == "" {
			t.Fatalf("test case %d failed with %d: %s; request was: %+v",
				tid, w.Code, w.Body.String(), req)
		}
		// verify that we got a proper signature response, with a valid signature
		var responses []signatureresponse
		err = json.Unmarshal(w.Body.Bytes(), &responses)
		if err != nil {
			t.Fatal(err)
		}
		if len(responses) != len(testcase.sgs) {
			t.Fatalf("test case %d failed to receive as many responses (%d) as we sent requests (%d)",
				tid, len(responses), len(testcase.sgs))
		}
		for i, response := range responses {
			if !verifyContentSignature(t, testcase.sgs[i].Input, response, "/sign/data") {
				t.Fatalf("test case %d signature verification failed in response %d; request was: %+v",
					tid, i, req)
			}
		}
	}
}

// verify that user `bob` is not allowed to sign with `appkey1`
func TestSignerUnauthorized(t *testing.T) {
	var TESTCASES = []signaturerequest{
		// request signature that need to prepend the content-signature:\x00 header
		signaturerequest{
			Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
			KeyID: conf.Authorizations[0].Signers[0],
		},
		signaturerequest{
			Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
			KeyID: conf.Authorizations[0].Signers[0],
		},
	}
	userid := conf.Authorizations[1].ID
	body, err := json.Marshal(TESTCASES)
	if err != nil {
		t.Fatal(err)
	}
	rdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, ag.auths[userid].ID, ag.auths[userid].Key,
		sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleSignature(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected to fail with %d but got %d: %s; request was: %+v", http.StatusUnauthorized, w.Code, w.Body.String(), req)
	}
}

func TestContentType(t *testing.T) {
	delete(sr.entry, "-")
	var TESTCASES = []signaturerequest{
		signaturerequest{
			Input: "Y2FyaWJvdXZpbmRpZXV4Cg==",
		},
	}
	userid := conf.Authorizations[0].ID
	body, err := json.Marshal(TESTCASES)
	if err != nil {
		t.Fatal(err)
	}
	rdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/sign/data", rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, ag.auths[userid].ID, ag.auths[userid].Key,
		sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleSignature(w, req)
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected response with content type 'application/json' but got %q instead",
			w.Header().Get("Content-Type"))
	}
}

func TestDebug(t *testing.T) {
	ag.enableDebug()
	if !ag.debug {
		t.Fatalf("expected debug mode to be enabled, but is disabled")
	}
	ag.disableDebug()
	if ag.debug {
		t.Fatalf("expected debug mode to be disabled, but is enabled")
	}
}

func getAuthHeader(req *http.Request, user, token string, hash func() hash.Hash, ext, contenttype string, payload []byte) string {
	auth := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   user,
			Key:  token,
			Hash: hash},
		0)
	auth.Ext = ext
	payloadhash := auth.PayloadHash(contenttype)
	payloadhash.Write(payload)
	auth.SetHash(payloadhash)
	return auth.RequestHeader()
}

// verify an ecdsa signature
func verifyContentSignature(t *testing.T, inputB64 string, response signatureresponse, endpoint string) bool {
	keyBytes, err := base64.StdEncoding.DecodeString(response.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := keyInterface.(*ecdsa.PublicKey)

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint == "/sign/data" {
		var templated []byte
		templated = make([]byte, len("Content-Signature:\x00")+len(input))
		copy(templated[:len("Content-Signature:\x00")], []byte("Content-Signature:\x00"))
		copy(templated[len("Content-Signature:\x00"):], input)

		var md hash.Hash
		switch pubKey.Params().Name {
		case "P-256":
			md = sha256.New()
		case "P-384":
			md = sha512.New384()
		case "P-521":
			md = sha512.New()
		default:
			t.Fatalf("unsupported curve algorithm %q", pubKey.Params().Name)
		}
		md.Write(templated)
		input = md.Sum(nil)
	}

	sig, err := contentsignature.Unmarshal(response.Signature)
	if err != nil {
		t.Fatal(err)
	}
	return ecdsa.Verify(pubKey, input, sig.R, sig.S)
}

func verifyXPI(t *testing.T, inputB64 string, response signatureresponse) bool {
	return true
}
