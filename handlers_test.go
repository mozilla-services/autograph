// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mozilla-services/autograph/database"
	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer/apk2"
	"github.com/mozilla-services/autograph/signer/contentsignature"
	"github.com/mozilla-services/autograph/signer/xpi"
	"go.mozilla.org/hawk"

	margo "go.mozilla.org/mar"
)

func TestBadRequest(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		endpoint string
		method   string
		body     string
	}{
		// missing request body
		{`/sign/data`, `POST`, ``},
		{`/sign/hash`, `POST`, ``},
		// invalid json body
		{`/sign/data`, `POST`, `{|||...........`},
		{`/sign/hash`, `POST`, `{|||...........`},
		// missing input
		{`/sign/data`, `POST`, `[{"input": "", "keyid": "abcd"}]`},
		{`/sign/hash`, `POST`, `[{"input": "", "keyid": "abcd"}]`},
		// input not in base64
		{`/sign/data`, `POST`, `[{"input": "......."}]`},
		{`/sign/hash`, `POST`, `[{"input": "......."}]`},
		// asking for a xpi signature using a hash will fail
		{`/sign/hash`, `POST`, `[{"input": "Y2FyaWJvdW1hdXJpY2UK", "keyid": "webextensions-rsa"}]`},
	}
	for i, testcase := range TESTCASES {
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest(testcase.method, "http://foo.bar"+testcase.endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		auth, err := ag.getAuthByID(conf.Authorizations[0].ID)
		if err != nil {
			t.Fatal(err)
		}

		authheader := getAuthHeader(req,
			auth.ID,
			auth.Key,
			sha256.New, id(),
			"application/json",
			[]byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code == http.StatusCreated {
			t.Fatalf("test case %d should have failed, but succeeded with %d: %s", i, w.Code, w.Body.String())
		}
	}
}

func TestRequestTooLarge(t *testing.T) {
	t.Parallel()

	blob := strings.Repeat("foobar", 200)
	body := strings.NewReader(blob)
	req, err := http.NewRequest("GET", "http://foo.bar/sign/data", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	auth, err := ag.getAuthByID(conf.Authorizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	authheader := getAuthHeader(req,
		auth.ID,
		auth.Key,
		sha256.New, id(),
		"application/json",
		[]byte(blob))
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleSignature(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("large request should have failed, but succeeded with %d: %s", w.Code, w.Body.String())
	}
}

func TestBadContentType(t *testing.T) {
	t.Parallel()

	blob := "foofoofoofoofoofoofoofoofoofoofoofoofoofoo"
	body := strings.NewReader(blob)
	req, err := http.NewRequest("GET", "http://foo.bar/sign/data", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/foobar")
	auth, err := ag.getAuthByID(conf.Authorizations[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	authheader := getAuthHeader(req,
		auth.ID,
		auth.Key,
		sha256.New, id(),
		"application/foobar",
		[]byte(blob))
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleSignature(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad content type request should have failed, but succeeded with %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthFail(t *testing.T) {
	t.Parallel()

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

func TestLBHeartbeat(t *testing.T) {
	t.Parallel()

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
		req, err := http.NewRequest(testcase.method, "http://foo.bar/__lbheartbeat__", nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handleLBHeartbeat(w, req)
		if w.Code != testcase.expect {
			t.Fatalf("test case %d failed with code %d but %d was expected",
				i, w.Code, testcase.expect)
		}
	}
}

func checkHeartbeatReturnsExpectedStatusAndBody(t *testing.T, name, method string, expectedStatusCode int, expectedBody []byte) {
	req, err := http.NewRequest(method, "http://foo.bar/__heartbeat__", nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ag.handleHeartbeat(w, req)
	if w.Code != expectedStatusCode {
		t.Fatalf("test case %s failed with code %d but %d was expected",
			name, w.Code, expectedStatusCode)
	}
	if !bytes.Equal(w.Body.Bytes(), expectedBody) {
		t.Fatalf("test case %s returned unexpected heartbeat body %q expected %q", name, w.Body.Bytes(), expectedBody)
	}
}

func TestHeartbeat(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		name               string
		method             string
		expectedHTTPStatus int
		expectedBody       string
	}{
		{"returns 200 for GET", `GET`, http.StatusOK, "{}"},
		{"returns 405 for POST", `POST`, http.StatusMethodNotAllowed, "POST method not allowed; endpoint accepts GET only\r\nrequest-id: -\n"},
		{"returns 405 for PUT", `PUT`, http.StatusMethodNotAllowed, "PUT method not allowed; endpoint accepts GET only\r\nrequest-id: -\n"},
		{"returns 405 for HEAD", `HEAD`, http.StatusMethodNotAllowed, "HEAD method not allowed; endpoint accepts GET only\r\nrequest-id: -\n"},
	}
	for _, testcase := range TESTCASES {
		checkHeartbeatReturnsExpectedStatusAndBody(t, testcase.name, testcase.method, testcase.expectedHTTPStatus, []byte((testcase.expectedBody)))
	}
}

func TestHeartbeatChecksHSMStatusFails(t *testing.T) {
	// NB: do not run in parallel with TestHeartbeat*
	ag.heartbeatConf = &heartbeatConfig{
		HSMCheckTimeout: time.Second,
		hsmSignerConf:   &ag.getSigners()[0].(*contentsignature.ContentSigner).Configuration,
	}

	expectedStatus := http.StatusInternalServerError
	expectedBody := []byte("{\"hsmAccessible\":false}")
	checkHeartbeatReturnsExpectedStatusAndBody(t, "returns 500 for GET with HSM inaccessible", `GET`, expectedStatus, expectedBody)

	ag.heartbeatConf = nil
}

func TestHeartbeatChecksHSMStatusFailsWhenNotConfigured(t *testing.T) {
	// NB: do not run in parallel with TestHeartbeat*
	ag.heartbeatConf = nil

	expectedStatus := http.StatusInternalServerError
	expectedBody := []byte("Missing heartbeat config\r\nrequest-id: -\n")
	checkHeartbeatReturnsExpectedStatusAndBody(t, "returns 500 for GET without heartbeat config HSM", `GET`, expectedStatus, expectedBody)
}

func TestHeartbeatChecksDBStatusOKAndTimesout(t *testing.T) {
	// NB: do not run in parallel with TestHeartbeat* or DB tests
	host := database.GetTestDBHost()
	db, err := database.Connect(database.Config{
		Name:     "autograph",
		User:     "myautographdbuser",
		Password: "myautographdbpassword",
		Host:     host + ":5432",
	})
	if err != nil {
		t.Fatal(err)
	}
	ag.db = db
	ag.heartbeatConf = &heartbeatConfig{
		DBCheckTimeout: 2 * time.Second,
	}

	// check OK run locally requires running DB container
	expectedStatus := http.StatusOK
	expectedBody := []byte("{\"dbAccessible\":true}")
	checkHeartbeatReturnsExpectedStatusAndBody(t, "returns 200 for GET with DB accessible", `GET`, expectedStatus, expectedBody)

	// drop timeout
	ag.heartbeatConf.DBCheckTimeout = 1 * time.Nanosecond
	// check DB request times out
	expectedStatus = http.StatusOK
	expectedBody = []byte("{\"dbAccessible\":false}")
	checkHeartbeatReturnsExpectedStatusAndBody(t, "returns 200 for GET with DB time out", `GET`, expectedStatus, expectedBody)

	// restore longer timeout and close the DB connection
	ag.heartbeatConf.DBCheckTimeout = 1 * time.Second
	db.Close()
	// check DB request still fails
	expectedStatus = http.StatusOK
	expectedBody = []byte("{\"dbAccessible\":false}")
	checkHeartbeatReturnsExpectedStatusAndBody(t, "returns 200 for GET with DB inaccessible", `GET`, expectedStatus, expectedBody)

	ag.db = nil
}

func TestVersion(t *testing.T) {
	t.Parallel()

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

// verify that user `alice` and `bob` are allowed to sign
// with their respective keys:
// * `appkey1` and `appkey2` for `alice`
// * `appkey2` only for `bob`
func TestSignerAuthorized(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		userid string
		sgs    []formats.SignatureRequest
	}{
		{
			userid: conf.Authorizations[0].ID,
			sgs: []formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: conf.Authorizations[0].Signers[0],
				},
				formats.SignatureRequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
					KeyID: conf.Authorizations[0].Signers[0],
				},
				formats.SignatureRequest{
					Input: "Q29udGVudC1TaWduYXR1cmU6ADwhRE9DVFlQRSBIVE1MPgo8aHRtbD4KPCEtLSBodHRwczovL2J1Z3ppbGxhLm1vemlsbGEub3JnL3Nob3dfYnVnLmNnaT9pZD0xMjI2OTI4IC0tPgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPHRpdGxlPlRlc3RwYWdlIGZvciBidWcgMTIyNjkyODwvdGl0bGU+CjwvaGVhZD4KPGJvZHk+CiAgSnVzdCBhIGZ1bGx5IGdvb2QgdGVzdHBhZ2UgZm9yIEJ1ZyAxMjI2OTI4PGJyLz4KPC9ib2R5Pgo8L2h0bWw+Cg==",
					KeyID: conf.Authorizations[0].Signers[1],
				},
			},
		},
		{
			userid: conf.Authorizations[1].ID,
			sgs: []formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: conf.Authorizations[1].Signers[0],
				},
				formats.SignatureRequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
					KeyID: conf.Authorizations[1].Signers[0],
				},
			},
		},
	}
	for tid, testcase := range TESTCASES {
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
		req.Header.Set("Content-Type", "application/json")
		auth, err := ag.getAuthByID(userid)
		if err != nil {
			t.Fatal(err)
		}

		authheader := getAuthHeader(req, auth.ID, auth.Key,
			sha256.New, id(), "application/json", body)
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusCreated || w.Body.String() == "" {
			t.Fatalf("test case %d failed with %d: %s; request was: %+v",
				tid, w.Code, w.Body.String(), req)
		}
		// verify that we got a proper signature response, with a valid signature
		var responses []formats.SignatureResponse
		err = json.Unmarshal(w.Body.Bytes(), &responses)
		if err != nil {
			t.Fatal(err)
		}
		if len(responses) != len(testcase.sgs) {
			t.Fatalf("test case %d failed to receive as many responses (%d) as we sent requests (%d)",
				tid, len(responses), len(testcase.sgs))
		}
		for i, response := range responses {
			err = verifyContentSignature(
				testcase.sgs[i].Input,
				"/sign/data",
				response.Signature,
				response.PublicKey)
			if err != nil {
				t.Fatalf("test case %d signature verification failed in response %d; request was: %+v",
					tid, i, req)
			}
		}
	}
}

// verify that user `bob` is not allowed to sign with `appkey1`
func TestSignerUnauthorized(t *testing.T) {
	t.Parallel()

	var TESTCASES = []formats.SignatureRequest{
		// request signature that need to prepend the content-signature:\x00 header
		formats.SignatureRequest{
			Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
			KeyID: conf.Authorizations[0].Signers[0],
		},
		formats.SignatureRequest{
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
	auth, err := ag.getAuthByID(userid)
	if err != nil {
		t.Fatal(err)
	}
	authheader := getAuthHeader(req, auth.ID, auth.Key,
		sha256.New, id(), "application/json", body)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleSignature(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected to fail with %d but got %d: %s; request was: %+v", http.StatusUnauthorized, w.Code, w.Body.String(), req)
	}
}

func TestContentType(t *testing.T) {
	t.Parallel()

	var TESTCASES = []formats.SignatureRequest{
		formats.SignatureRequest{
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
	auth, err := ag.getAuthByID(userid)
	if err != nil {
		t.Fatal(err)
	}
	authheader := getAuthHeader(req, auth.ID, auth.Key,
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

func verifyXPISignature(input, sig string) error {
	rawInput, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	pkcs7Sig, err := xpi.Unmarshal(sig, []byte(rawInput))
	if err != nil {
		log.Fatal(err)
	}
	return pkcs7Sig.VerifyWithChain(nil)
}

// verify an ecdsa signature
func verifyContentSignature(input, endpoint, signature, pubkey string) error {
	sig, err := contentsignature.Unmarshal(signature)
	if err != nil {
		return err
	}
	key, err := parsePublicKeyFromB64(pubkey)
	if err != nil {
		return err
	}
	rawInput, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	if endpoint == "/sign/data" || endpoint == "/__monitor__" {
		var templated []byte
		templated = make([]byte, len(contentsignature.SignaturePrefix)+len(rawInput))
		copy(templated[:len(contentsignature.SignaturePrefix)], []byte(contentsignature.SignaturePrefix))
		copy(templated[len(contentsignature.SignaturePrefix):], rawInput)

		var md hash.Hash
		switch sig.HashName {
		case "sha256":
			md = sha256.New()
		case "sha384":
			md = sha512.New384()
		case "sha512":
			md = sha512.New()
		default:
			return fmt.Errorf("unsupported hash algorithm %q", sig.HashName)
		}
		md.Write(templated)
		rawInput = md.Sum(nil)
	}
	if !ecdsa.Verify(key, rawInput, sig.R, sig.S) {
		return fmt.Errorf("ecdsa signature verification failed")
	}
	return nil
}

func verifyAPKManifestSignature(input, sig string) error {
	rawInput, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	pkcs7Sig, err := apk2.Unmarshal(sig, []byte(rawInput))
	if err != nil {
		log.Fatal(err)
	}
	return pkcs7Sig.Verify()
}

func verifyAPKSignature(signedAPK []byte) error {
	zipReader := bytes.NewReader(signedAPK)
	r, err := zip.NewReader(zipReader, int64(len(signedAPK)))
	if err != nil {
		return err
	}
	var (
		sigstr  string
		sigdata []byte
	)
	for _, f := range r.File {
		switch f.Name {
		case "META-INF/SIGNATURE.SF", "META-INF/APK2_TES.SF":
			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				return err
			}
			sigdata, err = ioutil.ReadAll(rc)
			if err != nil {
				return err
			}
		case "META-INF/SIGNATURE.RSA", "META-INF/APK2_TES.RSA":
			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				return err
			}
			rawsig, err := ioutil.ReadAll(rc)
			if err != nil {
				return err
			}
			sigstr = base64.StdEncoding.EncodeToString(rawsig)
		}
	}
	// convert string format back to signature
	sig, err := apk2.Unmarshal(sigstr, sigdata)
	if err != nil {
		return fmt.Errorf("failed to unmarshal signature: %v", err)
	}
	// verify signature on input data
	if sig.Verify() != nil {
		return fmt.Errorf("failed to verify apk signature: %v", sig.Verify())
	}
	return nil
}

func verifyMARSignature(b64Input, b64Sig, b64Key string, sigalg uint32) error {
	input, err := base64.StdEncoding.DecodeString(b64Input)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return err
	}
	rawKey, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return err
	}
	key, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return err
	}
	return margo.VerifySignature(input, sig, sigalg, key)
}

func parsePublicKeyFromB64(b64PubKey string) (pubkey *ecdsa.PublicKey, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(b64PubKey)
	if err != nil {
		return pubkey, fmt.Errorf("Failed to parse public key base64: %v", err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return pubkey, fmt.Errorf("Failed to parse public key DER: %v", err)
	}
	pubkey = keyInterface.(*ecdsa.PublicKey)
	return pubkey, nil
}
