// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package contentsignature

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mozilla-services/autograph/signer"
	verifier "github.com/mozilla-services/autograph/verifier/contentsignature"
)

func TestSign(t *testing.T) {
	input := []byte("foobarbaz1234abcd")
	for i, testcase := range PASSINGTESTCASES {
		// initialize a signer
		s, err := New(testcase.cfg)
		if err != nil {
			t.Fatalf("testcase %d signer initialization failed with: %v", i, err)
		}
		if s.Type != testcase.cfg.Type {
			t.Fatalf("testcase %d signer type %q does not match configuration %q", i, s.Type, testcase.cfg.Type)
		}
		if s.ID != testcase.cfg.ID {
			t.Fatalf("testcase %d signer id %q does not match configuration %q", i, s.ID, testcase.cfg.ID)
		}
		if s.PrivateKey != testcase.cfg.PrivateKey {
			t.Fatalf("testcase %d signer private key %q does not match configuration %q", i, s.PrivateKey, testcase.cfg.PrivateKey)
		}
		if s.Mode != testcase.cfg.ID {
			t.Fatalf("testcase %d signer curve %q does not match expected %q", i, s.Mode, testcase.cfg.ID)
		}

		// compare configs
		c1, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("testcase %d failed to json marshal signer: %v", i, err)
		}
		c2, err := json.Marshal(s.Config())
		if err != nil {
			t.Fatalf("testcase %d failed to json marshal signer config: %v", i, err)
		}
		if string(c1) != string(c2) {
			t.Fatalf("testcase %d configurations don't match:\nc1=%s\nc2=%s", i, c1, c2)
		}

		// sign input data
		sig, err := s.SignData(input, nil)
		if err != nil {
			t.Fatalf("testcase %d failed to sign data: %v", i, err)
		}
		// convert signature to string format
		sigstr, err := sig.Marshal()
		if err != nil {
			t.Fatalf("testcase %d failed to marshal signature: %v", i, err)
		}

		// convert string format back to signature
		cs, err := verifier.Unmarshal(sigstr)
		if err != nil {
			t.Fatalf("testcase %d failed to unmarshal signature: %v", i, err)
		}

		// make sure we still have the same string representation
		sigstr2, err := cs.Marshal()
		if err != nil {
			t.Fatalf("testcase %d failed to re-marshal signature: %v", i, err)
		}
		if sigstr != sigstr2 {
			t.Fatalf("testcase %d marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
				i, sigstr, sigstr2)
		}

		if cs.Len != getSignatureLen(s.Mode) {
			t.Fatalf("testcase %d expected signature len of %d, got %d",
				i, getSignatureLen(s.Mode), cs.Len)
		}
		if cs.Mode != s.Mode {
			t.Fatalf("testcase %d expected curve name %q, got %q", i, s.Mode, cs.Mode)
		}

		// decode public key
		keyBytes, err := base64.StdEncoding.DecodeString(s.PublicKey)
		if err != nil {
			t.Fatalf("testcase %d ailed to parse public key: %v", i, err)
		}
		keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			t.Fatalf("testcase %d failed to parse public key DER: %v", i, err)
		}
		pubkey := keyInterface.(*ecdsa.PublicKey)

		// verify signature on input data
		if !cs.VerifyData(input, pubkey) {
			t.Fatalf("testcase %d failed to verify content signature", i)
		}
	}
}

var PASSINGTESTCASES = []struct {
	cfg signer.Configuration
}{
	{cfg: signer.Configuration{
		Type: Type,
		ID:   P256ECDSA,
		X5U:  "https://foo.bar/chain.pem",
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
-----END EC PRIVATE KEY-----`,
	}},
	{cfg: signer.Configuration{
		Type: Type,
		ID:   P384ECDSA,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
/5Cp6z37rpp781N4haUOIauM14P4KUw=
-----END EC PRIVATE KEY-----`,
	}},
	{cfg: signer.Configuration{
		Type: Type,
		ID:   P521ECDSA,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBb+JY2KAiKqVOycgfvf9wH4onO93x6Dy/3bHuzj6wmW4rSAmuNHPq
yzdZSKDGPG5RxqdhgukMGwwrBgPfFJv5nDGgBwYFK4EEACOhgYkDgYYABAAVXz2h
oKyWlpcSecUoJgrvljyu/bSD7Z+onU7vT/FUFFaMK8fgwv3LVWQR8xgoAVWLiiiu
hB8RHyT8OaePachoHAFNFqVcGFkGZOLj2m60HH9tNTb1tBMDE08FBtcE7wImRn94
b/r392628ghQ8x7A4JzUvp0InWipIV0g+tJ4tw0hWw==
-----END EC PRIVATE KEY-----`,
	}},
}

func TestNewFailure(t *testing.T) {
	TESTCASES := []struct {
		err string
		cfg signer.Configuration
	}{
		{err: "contentsignature: invalid type", cfg: signer.Configuration{Type: ""}},
		{err: "contentsignature: missing signer ID in signer configuration", cfg: signer.Configuration{Type: Type, ID: ""}},
		{err: "contentsignature: missing private key in signer configuration", cfg: signer.Configuration{Type: Type, ID: "bob"}},
		{err: "contentsignature: failed to retrieve signer: no suitable key found", cfg: signer.Configuration{Type: Type, ID: "bob", PrivateKey: "Ym9iCg=="}},
		{err: "contentsignature: invalid private key algorithm, must be ecdsa", cfg: signer.Configuration{
			Type: Type,
			ID:   "abcd",
			PrivateKey: `
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALN6oewBN6fJyDErP9IbvLJex6LcSAljchZdj4eGaWttgseYqrww
xNVONln72JzOmZqXzxITxqi4tpFsrOqw780CAwEAAQJBAKMcSBvb32C1mSJWU+H3
Iz5XtMbluvINVpnM3awlE5l0nmA9vt0DE6iwFIwOPdY8HuliuVE5uIMloR+P5th1
IAECIQDlynpmy3WCApgfZS2CyYG7nOvWpCOpwgckm0uOjWQfAQIhAMfzIPOJBDli
ogU63yRBtCOZDYKtMbaDvXvLfKjeIBzNAiEA4otLPzrJH6K1HQaf5rgI6dEcBWGP
M1ZxulpMFD86/QECIAY+AuNXfbhE6gX7xoedPYB3AML5oTmvdzTsL2IePSZpAiBl
w2hKSJpdD11n9tJEQ7MieRzrqr58rqm9tymUH0rKIg==
-----END RSA PRIVATE KEY-----`,
		}},
	}
	for _, testcase := range TESTCASES {
		_, err := New(testcase.cfg)
		if !strings.Contains(err.Error(), testcase.err) {
			t.Fatalf("expected to fail with '%v' but failed with '%v' instead", testcase.err, err)
		}
		if err == nil {
			t.Fatalf("expected to fail with '%v' but succeeded", testcase.err)
		}
	}
}

func TestNoShortData(t *testing.T) {
	s, err := New(PASSINGTESTCASES[0].cfg)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	_, err = s.SignData([]byte("a"), nil)
	if err == nil {
		t.Fatal("expected to fail with input data too short but succeeded")
	}
	if err.Error() != "contentsignature: refusing to sign input data shorter than 10 bytes" {
		t.Fatalf("expected to fail with input data too short but failed with: %v", err)
	}
}
