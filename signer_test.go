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
			t.Errorf("expiected to fail with '%v' but succeeded", testcase.expectError)
		}
	}
}

func TestFromB64URL(t *testing.T) {
	TESTCASES := []struct {
		expectError string
		b64         string
		sig         []byte
	}{
		{"illegal base64 data at input byte 0", "{{{{{{", nil},
		{"", "XBKzej3i6TAFZc3VZsuCekn-4dYWJBE4-b3OOtKrOV-JIzIvAnAhnOV1aj-kEm07kh-FciIxV-Xk2QUQlRQzHO7oW7E4mXkMKkbbAcvL0CFrItTObhfhKnBnpAE9ql1O", []byte("\x5c\x12\xb3\x7a\x3d\xe2\xe9\x30\x05\x65\xcd\xd5\x66\xcb\x82\x7a\x49\xfe\xe1\xd6\x16\x24\x11\x38\xf9\xbd\xce\x3a\xd2\xab\x39\x5f\x89\x23\x32\x2f\x02\x70\x21\x9c\xe5\x75\x6a\x3f\xa4\x12\x6d\x3b\x92\x1f\x85\x72\x22\x31\x57\xe5\xe4\xd9\x05\x10\x95\x14\x33\x1c\xee\xe8\x5b\xb1\x38\x99\x79\x0c\x2a\x46\xdb\x01\xcb\xcb\xd0\x21\x6b\x22\xd4\xce\x6e\x17\xe1\x2a\x70\x67\xa4\x01\x3d\xaa\x5d\x4e")},
	}
	for _, testcase := range TESTCASES {
		var s signature
		err := s.fromBase64Url(testcase.b64)
		if testcase.expectError == "" && err != nil {
			t.Errorf("failed to load signature from base64 data: %v", err)
		}
		if testcase.expectError != "" && testcase.expectError != err.Error() {
			t.Errorf("expected to fail with error %q but got error %q", testcase.expectError, err)
		}
		if testcase.expectError == "" && err == nil {
			if !bytes.Equal(testcase.sig, s) {
				t.Errorf("decoded base64 data doesn't match expected data")
			}
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

func TestGetCertificate(t *testing.T) {
	c, err := ag.signers[0].getCertificate()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := fromBase64URL(c.EncryptionKey)
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
