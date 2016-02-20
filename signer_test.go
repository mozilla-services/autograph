// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"testing"
)

func TestInitFail(t *testing.T) {
	TESTCASES := []struct {
		expectError string
		s           signer
	}{
		{expectError: "missing signer ID in signer configuration", s: signer{ID: ""}},
		{expectError: "missing private key in signer configuration", s: signer{ID: "bob"}},
		{expectError: "illegal base64 data at input byte 0", s: signer{ID: "bob", PrivateKey: "{{{{"}},
		{expectError: "x509: failed to parse EC private key: asn1: structure error: tags don't match (16 vs {class:1 tag:2 length:111 isCompound:true}) {optional:false explicit:false application:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} ecPrivateKey @2", s: signer{ID: "bob", PrivateKey: "Ym9iCg=="}},
	}
	for _, testcase := range TESTCASES {
		err := testcase.s.init()
		if err.Error() != testcase.expectError {
			t.Errorf("expected to fail with '%v' but failed with '%v' instead", testcase.expectError, err)
		}
		if err == nil {
			t.Errorf("expected to fail with '%v' but succeeded", testcase.expectError)
		}
	}
}

func TestGetInputHash(t *testing.T) {
	TESTCASES := []struct {
		sigreq      signaturerequest
		hash        string
		expectError string
	}{
		// hash a string with sha384
		{sigreq: signaturerequest{Input: "Y2FyaWJvdW1hdXJpY2UK", HashWith: "sha384"}, hash: "7e0509bd09f58d97575f6fcf06358e90fa47dfceecfc93694933352685287f11656fd060f116225c2bfd1954f5a31748"},
		// apply a template to the string then hash it with sha384
		{sigreq: signaturerequest{Template: "content-signature", Input: "Y2FyaWJvdW1hdXJpY2UK", HashWith: "sha384"}, hash: "e8c5eecea3e754b7028438b1f61174a695369c3eef603b7ebbf50cf906ce65425855d1d3c7e4a7c5d5e63c765ddd0699"},
		// string already hashed, return it untouched
		{sigreq: signaturerequest{Input: "6MXuzqPnVLcChDix9hF0ppU2nD7vYDt+u/UM+QbOZUJYVdHTx+SnxdXmPHZd3QaZ"}, hash: "e8c5eecea3e754b7028438b1f61174a695369c3eef603b7ebbf50cf906ce65425855d1d3c7e4a7c5d5e63c765ddd0699"},
		// unsupported hash method
		{sigreq: signaturerequest{Input: "Y2FyaWJvdW1hdXJpY2UK", HashWith: "md5"}, expectError: `unsupported digest algorithm "md5"`},
		// unsupported template
		{sigreq: signaturerequest{Template: "caribou", Input: "Y2FyaWJvdW1hdXJpY2UK"}, expectError: `unknown template "caribou"`},
	}
	for i, testcase := range TESTCASES {
		hash, err := getInputHash(testcase.sigreq)
		if err != nil {
			if testcase.expectError == "" {
				t.Errorf("test case %d expected to succeed but failed with error: %v", i, err)
			} else if testcase.expectError != err.Error() {
				t.Errorf("test case %d expected to fail with %q but failed with %v", i, testcase.expectError, err)
			}
		}
		if testcase.expectError == "" {
			if testcase.hash != fmt.Sprintf("%x", hash) {
				t.Errorf("test case %d failed: expected hash %q, got %q",
					i, testcase.hash, fmt.Sprintf("%x", hash))
			}
		}
	}
}

func TestGetPubKey(t *testing.T) {
	pub, err := ag.signers[0].getPubKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := fromBase64URL(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(kb)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := keyInterface.(*ecdsa.PublicKey)
	if len(pubKey.X.String()) < 10 || len(pubKey.Y.String()) < 10 {
		t.Errorf("invalid X/Y values in public key: X=%s; Y=%s",
			pubKey.X.String(), pubkey.Y.String())
	}
}
