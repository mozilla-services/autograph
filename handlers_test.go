// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var (
	ag     *autographer
	pubkey *ecdsa.PublicKey
)

func TestMain(m *testing.M) {
	// load the signers
	ag = new(autographer)
	for _, sgc := range []Signer{Signer{PrivateKey: privatekey}} {
		sgc.init()
		ag.addSigner(sgc)
	}
	// parse the public key
	data, err := fromBase64URL(publickey)
	if err != nil {
		log.Fatal(err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		log.Fatal(err)
	}
	pubkey = keyInterface.(*ecdsa.PublicKey)
	// run the tests and exit
	r := m.Run()
	os.Exit(r)
}

func TestSignaturePass(t *testing.T) {
	var TESTCASES = []signaturerequest{
		// request signature that need to prepend the content-signature:\x00 header
		signaturerequest{
			Template: "content-signature",
			HashWith: "sha384",
			Input:    "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
		},
		// request signature of a precomputed sha384 hash
		signaturerequest{
			Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
		},
		// request signature of raw data that already has the content-signature header prepended
		signaturerequest{
			HashWith: "sha384",
			Input:    "Q29udGVudC1TaWduYXR1cmU6ADwhRE9DVFlQRSBIVE1MPgo8aHRtbD4KPCEtLSBodHRwczovL2J1Z3ppbGxhLm1vemlsbGEub3JnL3Nob3dfYnVnLmNnaT9pZD0xMjI2OTI4IC0tPgo8aGVhZD4KICA8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+CiAgPHRpdGxlPlRlc3RwYWdlIGZvciBidWcgMTIyNjkyODwvdGl0bGU+CjwvaGVhZD4KPGJvZHk+CiAgSnVzdCBhIGZ1bGx5IGdvb2QgdGVzdHBhZ2UgZm9yIEJ1ZyAxMjI2OTI4PGJyLz4KPC9ib2R5Pgo8L2h0bWw+Cg==",
		},
	}
	body, err := json.Marshal(TESTCASES)
	if err != nil {
		t.Fatal(err)
	}
	rdr := bytes.NewReader(body)
	req, err := http.NewRequest("POST", "http://foo.bar/signature", rdr)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ag.signature(w, req)
	if w.Code != 200 || w.Body.String() == "" {
		t.Fatalf("failed with %d: %s", w.Code, w.Body.String())
	}

	// verify that we got a proper signature response, with a valid signature
	var responses []signatureresponse
	err = json.Unmarshal(w.Body.Bytes(), &responses)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != len(TESTCASES) {
		t.Fatalf("failed to receive as many responses (%d) as we sent requests (%d)",
			len(responses), len(TESTCASES))
	}
	for i, response := range responses {
		if !verify(t, TESTCASES[i], response) {
			t.Fatalf("signature verification failed in response %d", i)
		}
	}
}

func TestSignatureFail(t *testing.T) {
	var TESTCASES = []struct {
		method string
		body   string
	}{
		{`GET`, `[{"signaturetype": "content-signature", "inputtype": "raw", "input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		{`POST`, ``},
		{`PUT`, ``},
		{`HEAD`, ``},
	}
	for i, testcase := range TESTCASES {
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest(testcase.method, "http://foo.bar/signature", body)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		ag.signature(w, req)
		if w.Code == 200 {
			t.Fatalf("test case %d failed with %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// verify an ecdsa signature
func verify(t *testing.T, request signaturerequest, response signatureresponse) bool {
	hash, err := getInputHash(request)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, sig := range response.Signatures {
		sigBytes, err := fromBase64URL(sig.Signature)
		if err != nil {
			t.Fatalf("failed to decode base64 signature data: %v", err)
		}
		r, s := new(big.Int), new(big.Int)
		r.SetBytes(sigBytes[:len(sigBytes)/2])
		s.SetBytes(sigBytes[len(sigBytes)/2:])
		if !ecdsa.Verify(pubkey, hash, r, s) {
			return false
		}
	}
	return true
}

const privatekey string = "MIGkAgEBBDAzX2TrGOr0WE92AbAl+nqnpqh25pKCLYNMTV2hJHztrkVPWOp8w0mhscIodK8RMpagBwYFK4EEACKhZANiAATiTcWYbt0Wg63dO7OXvpptNG0ryxv+v+JsJJ5Upr3pFus5fZyKxzP9NPzB+oFhL/xw3jMx7X5/vBGaQ2sJSiNlHVkqZgzYF6JQ4yUyiqTY7v67CyfUPA1BJg/nxOS9m3o="
const publickey string = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4k3FmG7dFoOt3Tuzl76abTRtK8sb/r/ibCSeVKa96RbrOX2ciscz/TT8wfqBYS/8cN4zMe1+f7wRmkNrCUojZR1ZKmYM2BeiUOMlMoqk2O7+uwsn1DwNQSYP58TkvZt6"
