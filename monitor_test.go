package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/apk2"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/contentsignaturepki"
	"go.mozilla.org/autograph/signer/genericrsa"
	"go.mozilla.org/autograph/signer/gpg2"
	"go.mozilla.org/autograph/signer/mar"
	"go.mozilla.org/autograph/signer/pgp"
	"go.mozilla.org/autograph/signer/rsapss"
	"go.mozilla.org/autograph/signer/xpi"
	margo "go.mozilla.org/mar"
)

func TestMonitorPass(t *testing.T) {
	t.Parallel()

	var empty []byte
	req, err := http.NewRequest("GET", "http://foo.bar/__monitor__", bytes.NewReader(empty))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, "monitor", conf.Monitoring.Key,
		sha256.New, id(), "application/json", empty)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleMonitor(w, req)
	if w.Code != http.StatusCreated || w.Body.String() == "" {
		t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
	}
	// verify that we got a proper signature response, with a valid signature
	var responses []formats.SignatureResponse
	err = json.Unmarshal(w.Body.Bytes(), &responses)
	if err != nil {
		t.Fatal(err)
	}
	for i, response := range responses {
		switch response.Type {
		case contentsignature.Type:
			err = verifyContentSignature(
				base64.StdEncoding.EncodeToString(MonitoringInputData),
				"/__monitor__",
				response.Signature,
				response.PublicKey)
		case contentsignaturepki.Type:
			err = contentsignaturepki.Verify(response.X5U, response.Signature, MonitoringInputData)
		case xpi.Type:
			err = verifyXPISignature(
				base64.StdEncoding.EncodeToString(MonitoringInputData),
				response.Signature)
		case apk.Type:
			err = verifyAPKManifestSignature(
				base64.StdEncoding.EncodeToString(MonitoringInputData),
				response.Signature)
		case apk2.Type:
			signedfile, err := base64.StdEncoding.DecodeString(response.SignedFile)
			if err != nil {
				t.Fatalf("failed to base64 decode signed file")
			}
			err = verifyAPKSignature(signedfile)
		case mar.Type:
			err = verifyMARSignature(base64.StdEncoding.EncodeToString(MonitoringInputData),
				response.Signature, response.PublicKey, margo.SigAlgRsaPkcs1Sha384)
		case rsapss.Type:
			err = verifyRsapssSignature(response.Signature, response.PublicKey)
		case genericrsa.Type:
			err = genericrsa.VerifyGenericRsaSignatureResponse(MonitoringInputData, response)
		case pgp.Type, gpg2.Type:
			// we don't verify pgp signatures. I don't feel good about this, but the openpgp
			// package is very much a pain to deal with and requires putting the public key
			// into a keyring to verify a signature.
			continue
		default:
			t.Fatalf("unsupported signature type %q", response.Type)
		}
		if err != nil {
			t.Logf("%+v", response)
			t.Fatalf("verification of monitoring response %d failed: %v", i, err)
		}
	}
}

func verifyRsapssSignature(b64Sig, b64Key string) error {
	shasum := sha1.Sum(MonitoringInputData)
	digest := base64.StdEncoding.EncodeToString(shasum[:])
	return rsapss.VerifySignatureFromB64(digest, b64Sig, b64Key)
}

func TestMonitorHasSignerParameters(t *testing.T) {
	t.Parallel()

	var empty []byte
	req, err := http.NewRequest("GET", "http://foo.bar/__monitor__", bytes.NewReader(empty))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, "monitor", conf.Monitoring.Key,
		sha256.New, id(), "application/json", empty)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	ag.handleMonitor(w, req)
	if w.Code != http.StatusCreated || w.Body.String() == "" {
		t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
	}
	// verify that we got a proper signature response, with a valid signature
	var responses []formats.SignatureResponse
	err = json.Unmarshal(w.Body.Bytes(), &responses)
	if err != nil {
		t.Fatal(err)
	}
	for i, response := range responses {
		switch response.Type {
		case contentsignature.Type:
			for _, s := range ag.signers {
				if response.SignerID == s.Config().ID {
					if response.X5U != s.Config().X5U {
						t.Fatalf("X5U in signature response %d does not match its signer: expected %q got %q",
							i, s.Config().X5U, response.X5U)
					}
					if response.Type != s.Config().Type {
						t.Fatalf("Type of signature response %d does not match its signer: expected %q got %q",
							i, s.Config().Type, response.Type)
					}
					if response.Mode != s.Config().Mode {
						t.Fatalf("Mode of signature response %d does not match its signer: expected %q got %q",
							i, s.Config().Mode, response.Mode)
					}
					if response.PublicKey != s.Config().PublicKey {
						t.Fatalf("Public Key of signature response %d does not match its signer: expected %q got %q",
							i, s.Config().PublicKey, response.PublicKey)
					}
				}
			}
		}
	}
}

func TestMonitorNoConfig(t *testing.T) {
	t.Parallel()

	tmpag := newAutographer(1)
	var nomonitor configuration
	tmpag.addMonitoring(nomonitor.Monitoring)
	if _, ok := tmpag.auths["monitor"]; ok {
		t.Fatal("monitor configuration found when none was passed")
	}
}

func TestMonitorAddDuplicate(t *testing.T) {
	t.Parallel()

	tmpag := newAutographer(1)
	var monitorconf configuration
	monitorconf.Monitoring.Key = "xxxxxxx"

	defer func() {
		if e := recover(); e != nil {
			if e != `user 'monitor' is reserved for monitoring, duplication is not permitted` {
				t.Fatalf("expected authorization loading to fail with duplicate error but got: %v", e)
			}
		}
	}()
	// Adding the first one will pass, adding the second one will trigger the panic
	tmpag.addMonitoring(monitorconf.Monitoring)
	tmpag.addMonitoring(monitorconf.Monitoring)
}

func TestMonitorBadRequest(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		user     string
		key      string
		endpoint string
		method   string
		body     string
	}{
		// wrong method
		{``, ``, `/__monitor__`, `POST`, ``},
		{``, ``, `/__monitor__`, `PUT`, ``},
		{``, ``, `/__monitor__`, `HEAD`, ``},
		{``, ``, `/__monitor__`, `DELETE`, ``},
		// shouldn't have a request body
		{`monitor`, conf.Monitoring.Key, `/__monitor__`, `GET`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// should use the monitor user
		{conf.Authorizations[0].ID, conf.Authorizations[0].Key, `/__monitor__`, `GET`, ``},
		// should use the monitoring key
		{`monitor`, conf.Authorizations[0].Key, `/__monitor__`, `GET`, ``},
	}
	for i, testcase := range TESTCASES {
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest(testcase.method, "http://foo.bar"+testcase.endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, testcase.user, testcase.key, sha256.New, id(), "application/json", []byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		ag.handleMonitor(w, req)
		if w.Code == http.StatusCreated {
			t.Fatalf("test case %d failed with %d: %s", i, w.Code, w.Body.String())
		}
	}
}
