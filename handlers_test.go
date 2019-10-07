// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"go.mozilla.org/autograph/signer/apk2"
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

	"go.mozilla.org/autograph/database"
	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/mar"
	"go.mozilla.org/autograph/signer/xpi"
	"go.mozilla.org/hawk"

	margo "go.mozilla.org/mar"
)

func TestSignaturePass(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		endpoint          string
		signaturerequests []formats.SignatureRequest
	}{
		{
			// Sign hash with Content Signature
			"/sign/hash",
			[]formats.SignatureRequest{
				// request signature of a precomputed sha384 hash
				formats.SignatureRequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
					KeyID: "appkey1",
				},
			},
		},
		{
			// Sign a regular add-on
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUtRGlnZXN0LU1hbmlmZXN0OiA3d3RFNTF2bW00NlZQRmEvNkF0NWZ3PT0KU0hBMS1EaWdlc3QtTWFuaWZlc3Q6IEZMZEFIZHQvVjdFVHozK0JMUUtHcFFBenoyRT0KCg==",
					KeyID: "webextensions-rsa",
					Options: map[string]string{
						"id": "test@example.net",
					},
				},
			},
		},
		{
			// Sign an extension
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUtRGlnZXN0LU1hbmlmZXN0OiA3d3RFNTF2bW00NlZQRmEvNkF0NWZ3PT0KU0hBMS1EaWdlc3QtTWFuaWZlc3Q6IEZMZEFIZHQvVjdFVHozK0JMUUtHcFFBenoyRT0KCg==",
					KeyID: "extensions-ecdsa",
					Options: map[string]string{
						"id": "test@example.net",
					},
				},
			},
		},
		{
			// Sign data with Content-Signature
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: "appkey2",
				},
			},
		},
		{
			// Sign an APK manifest
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUtRGlnZXN0LU1hbmlmZXN0OiA3d3RFNTF2bW00NlZQRmEvNkF0NWZ3PT0KU0hBMS1EaWdlc3QtTWFuaWZlc3Q6IEZMZEFIZHQvVjdFVHozK0JMUUtHcFFBenoyRT0KCg==",
					KeyID: "testapp-android-legacy",
				},
			},
		},
		{
			// Sign an APK file
			"/sign/file",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "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",
					KeyID: "testapp-android",
				},
			},
		},
		{
			// Sign MAR data
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "Y2FyaWJvdW1hdXJpY2U=",
					KeyID: "testmar",
				},
			},
		},
		{
			// Sign a MAR file
			"/sign/file",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					// Input is the base64 of miniMarB from the mar signer unit tests
					Input: "TUFSMQAAAX0AAAAAAAABlgAAAAIAAAACAAABACDExrLgT1Lc1TbLUiKbIVxQl60L6ATvYe6L6JwewAbVSjhEUCGMQ0OK1TmKi18GGijNxaf/uU7Lm/RTyvm0VL7gcODm/pogDmRttf+rc2UfX7nthPxCgB/oOj7fXqDwYpiBPNSSHMIATUb7fnRRHqVTdqhkQZ2RqQsyKL7O6D/bN62EHmVTnn5LbYqYnDLhp+bEVGPo9ETsUpSk7XlFq3v96blLi4Iazm4LyPUXtQmixNwe6OOGpS+ZqobGAtooe7nPPC0Q/kqqKKQmcwCyTP/+lD1Vk7JXbDyGzYj9f9Cloq8PH7gyxOmNvwfHxMU95Jw/ExdFUDdK6QW7UPRTx7AAAAADAAAAQMSHgnYz95K8msSv6YA6IWRfT99ig0W74KDl0QvM0Ti+BRvI7FSmjjt4QOfVHRDko31NuVa2sUCo/PibauLI7GwAAAAAYWFhYWFhYWFhYWFhYWFhYWFhYWFhAAAAFQAAAWgAAAAVAAACWC9mb28vYmFyAA==",
					KeyID: "testmar",
				},
			},
		},
	}
	for i, testcase := range TESTCASES {
		userid := conf.Authorizations[0].ID
		body, err := json.Marshal(testcase.signaturerequests)
		if err != nil {
			t.Fatal(err)
		}
		rdr := bytes.NewReader(body)
		req, err := http.NewRequest("POST",
			"http://foo.bar"+testcase.endpoint,
			rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		// generate a hawk header for the request
		authheader := getAuthHeader(req,
			ag.auths[userid].ID,
			ag.auths[userid].Key,
			sha256.New,
			id(),
			"application/json",
			body)
		req.Header.Set("Authorization", authheader)

		// send the request to the handler
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusCreated || w.Body.String() == "" {
			t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
		}

		// parse the response
		var responses []formats.SignatureResponse
		err = json.Unmarshal(w.Body.Bytes(), &responses)
		if err != nil {
			t.Fatal(err)
		}

		// we should have received the same number of responses as we sent requests
		if len(responses) != len(testcase.signaturerequests) {
			t.Fatalf("in test case %d, failed to receive as many responses (%d) as we sent requests (%d)",
				i, len(responses), len(testcase.signaturerequests))
		}

		// verify the signature in each response
		for j, response := range responses {
			switch response.Type {
			case contentsignature.Type:
				err = verifyContentSignature(
					testcase.signaturerequests[j].Input,
					testcase.endpoint,
					response.Signature,
					response.PublicKey)
			case xpi.Type:
				err = verifyXPISignature(testcase.signaturerequests[j].Input, response.Signature)
			case apk.Type, apk2.Type:
				if req.URL.RequestURI() == "/sign/data" {
					// ok this is a bit of a hack but since apk signatures are really just pkcs7 we can
					// reuse the xpi verification code here...
					err = verifyAPKManifestSignature(testcase.signaturerequests[j].Input, response.Signature)
				} else {
					signedAPK, _ := base64.StdEncoding.DecodeString(response.SignedFile)
					err = verifyAPKSignature(signedAPK)
				}
			case mar.Type:
				switch req.URL.RequestURI() {
				case "/sign/file":
					// use the margo pkg to calculate the signable block of the mar file
					// as input for the signature verification
					rawInput, _ := base64.StdEncoding.DecodeString(testcase.signaturerequests[j].Input)
					var marFile margo.File
					margo.Unmarshal(rawInput, &marFile)
					rawKey, err := base64.StdEncoding.DecodeString(response.PublicKey)
					if err != nil {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					key, err := x509.ParsePKIXPublicKey(rawKey)
					if err != nil {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					err = marFile.VerifySignature(key)
				default:
					err = verifyMARSignature(testcase.signaturerequests[j].Input, response.Signature, response.PublicKey, margo.SigAlgRsaPkcs1Sha384)
				}
			default:
				err = fmt.Errorf("unknown signature type %q", response.Type)
			}
			if err != nil {
				t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v",
					i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
			}
		}
	}
}

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
		authheader := getAuthHeader(req,
			ag.auths[conf.Authorizations[0].ID].ID,
			ag.auths[conf.Authorizations[0].ID].Key,
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
	authheader := getAuthHeader(req,
		ag.auths[conf.Authorizations[0].ID].ID,
		ag.auths[conf.Authorizations[0].ID].Key,
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
	authheader := getAuthHeader(req,
		ag.auths[conf.Authorizations[0].ID].ID,
		ag.auths[conf.Authorizations[0].ID].Key,
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
		hsmSignerConf:   &ag.signers[0].(*contentsignature.ContentSigner).Configuration,
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
	db, err := database.Connect(database.Config{
		Name:     "autograph",
		User:     "myautographdbuser",
		Password: "myautographdbpassword",
		Host:     "127.0.0.1:5432",
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
	pkcs7Sig, err := apk.Unmarshal(sig, []byte(rawInput))
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
	sig, err := apk.Unmarshal(sigstr, sigdata)
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
