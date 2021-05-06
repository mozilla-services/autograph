// +build !race

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer/apk2"
	"github.com/mozilla-services/autograph/signer/contentsignature"
	"github.com/mozilla-services/autograph/signer/contentsignaturepki"
	"github.com/mozilla-services/autograph/signer/genericrsa"
	"github.com/mozilla-services/autograph/signer/gpg2"
	"github.com/mozilla-services/autograph/signer/mar"
	"github.com/mozilla-services/autograph/signer/xpi"
	csigverifier "github.com/mozilla-services/autograph/verifier/contentsignature"
	margo "go.mozilla.org/mar"
)

const autographDevRootHash = `5E:36:F2:14:DE:82:3F:8B:29:96:89:23:5F:03:41:AC:AF:A0:75:AF:82:CB:4C:D4:30:7C:3D:B3:43:39:2A:FE`

func TestMonitorPass(t *testing.T) {
	t.Parallel()

	var empty []byte
	req, err := http.NewRequest("GET", "http://foo.bar/__monitor__", bytes.NewReader(empty))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, monitorAuthID, conf.Monitoring.Key,
		sha256.New, id(), "application/json", empty)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	mo.handleMonitor(w, req)
	if w.Code != http.StatusCreated || w.Body.String() == "" {
		t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
	}

	dec := json.NewDecoder(w.Result().Body)
	for {
		// verify that we got a proper signature response, with a valid signature
		var response formats.SignatureResponse
		if err := dec.Decode(&response); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}

		switch response.Type {
		case contentsignature.Type:
			err = verifyContentSignature(
				base64.StdEncoding.EncodeToString(MonitoringInputData),
				response,
				"/__monitor__")
		case contentsignaturepki.Type:
			body, _, err := contentsignaturepki.GetX5U(response.X5U)
			if err != nil {
				t.Fatal(err)
			}
			err = csigverifier.Verify(MonitoringInputData, body, response.Signature, autographDevRootHash)
		case xpi.Type:
			err = verifyXPISignature(
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
		case genericrsa.Type:
			err = genericrsa.VerifyGenericRsaSignatureResponse(MonitoringInputData, response)
		case gpg2.Type:
			// we don't verify pgp signatures. I don't feel good about this, but the openpgp
			// package is very much a pain to deal with and requires putting the public key
			// into a keyring to verify a signature.
			continue
		default:
			t.Fatalf("unsupported signature type %q", response.Type)
		}
		if err != nil {
			t.Logf("%+v", response)
			t.Fatalf("verification of monitoring response failed: %v", err)
		}
	}
}

func TestMonitorHasSignerParameters(t *testing.T) {
	t.Parallel()

	var empty []byte
	req, err := http.NewRequest("GET", "http://foo.bar/__monitor__", bytes.NewReader(empty))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, monitorAuthID, conf.Monitoring.Key,
		sha256.New, id(), "application/json", empty)
	req.Header.Set("Authorization", authheader)
	w := httptest.NewRecorder()
	mo.handleMonitor(w, req)
	if w.Code != http.StatusCreated || w.Body.String() == "" {
		t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
	}

	dec := json.NewDecoder(w.Result().Body)
	for {
		// verify that we got a proper signature response, with a valid signature
		var response formats.SignatureResponse
		if err := dec.Decode(&response); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		switch response.Type {
		case contentsignature.Type:
			for _, s := range ag.getSigners() {
				if response.SignerID == s.Config().ID {
					if response.X5U != s.Config().X5U {
						t.Fatalf("X5U in signature response does not match its signer: expected %q got %q",
							s.Config().X5U, response.X5U)
					}
					if response.Type != s.Config().Type {
						t.Fatalf("Type of signature response does not match its signer: expected %q got %q",
							s.Config().Type, response.Type)
					}
					if response.Mode != s.Config().Mode {
						t.Fatalf("Mode of signature response does not match its signer: expected %q got %q",
							s.Config().Mode, response.Mode)
					}
					if response.PublicKey != s.Config().PublicKey {
						t.Fatalf("Public Key of signature response does not match its signer: expected %q got %q",
							s.Config().PublicKey, response.PublicKey)
					}
				}
			}
		}
	}
}
