// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package contentsignaturepki

import (
	"encoding/json"
	"strings"
	"testing"

	"go.mozilla.org/autograph/signer"
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
		if s.Mode != testcase.cfg.Mode {
			t.Fatalf("testcase %d signer curve %q does not match expected %q", i, s.Mode, testcase.cfg.Mode)
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
		cs, err := Unmarshal(sigstr)
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

	}
}

var PASSINGTESTCASES = []struct {
	cfg signer.Configuration
}{
	{cfg: signer.Configuration{
		Type:                Type,
		ID:                  "testsigner0",
		Mode:                P384ECDSA,
		X5U:                 "file:///tmp/autograph_unit_tests/chains/",
		ChainUploadLocation: "file:///tmp/autograph_unit_tests/chains/",
		PrivateKey: `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBcwxsHPTSHIVY1qLobCqBtnjRe0UZWOro1xtg2oV4rkypbkkgHHnSA
s8p0PlGIknKgBwYFK4EEACKhZANiAAQMBfcDj4r/9aAXcUsjjun3vCpBSQoskcdi
iF4bE+AcFmPABh6AnwTZv0sHYPjkovk3R3RfuXlKyoqhuD73VqBhkuK7R6mN2snh
fRkWmi6SzHWZIXPzFScoCaHnJrFzNjs=
-----END EC PRIVATE KEY-----`,
		PublicKey: `
-----BEGIN CERTIFICATE-----
MIICXDCCAeKgAwIBAgIIFYW6xg9HrnAwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODUxMDA2MB4XDTE4MTIyMTE1
NTY0NloXDTI5MDIyMjE1NTY0NlowYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
VQQDExFjc2ludGVyMTU1MDg1MTAwNjB2MBAGByqGSM49AgEGBSuBBAAiA2IABAwF
9wOPiv/1oBdxSyOO6fe8KkFJCiyRx2KIXhsT4BwWY8AGHoCfBNm/Swdg+OSi+TdH
dF+5eUrKiqG4PvdWoGGS4rtHqY3ayeF9GRaaLpLMdZkhc/MVJygJoecmsXM2O6Nq
MGgwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA8GA1UdEwEB
/wQFMAMBAf8wMAYDVR0eAQH/BCYwJKAiMCCCHi5jb250ZW50LXNpZ25hdHVyZS5t
b3ppbGxhLm9yZzAKBggqhkjOPQQDAwNoADBlAjBss+GLdMdLT2Y/g73OE9x0WyUG
vqzO7klt20yytmhaYMIPT/zRnWsHZbqEijHMzGsCMQDEoKetuWkyBkzAytS6l+ss
mYigBlwySY+gTqsjuIrydWlKaOv1GU+PXbwX0cQuaN8=
-----END CERTIFICATE-----`,
		CaCert: `
-----BEGIN CERTIFICATE-----
MIICKTCCAa+gAwIBAgIIFYW6xg2sw4QwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODUxMDA2MB4XDTE4MTIyMDE1
NTY0NloXDTQ5MDIyMjE1NTY0NlowXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRkwFwYD
VQQDExBjc3Jvb3QxNTUwODUxMDA2MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENrUI
9GJFild/ZVNwh7885643BhJlqTqZSas8mAUkYRDKv9lXk/r+CpLPclrwz/Po21xn
5SlibnOTXaOZdMlDcWCCKqNNGRyi1xPHJIfvtF6+CswJnrkthpy6dimqd0Tyozgw
NjAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjB3fOCz2SQvxNZ65juSotQNRvXhB4TZ
nsbYLErV5grBhN+UxzmY9YwlOl6j6CoBiNkCMQCVBh9UBkWNkUfMUGImrCNDLvlw
//Vb8kLBsJmLQjZNbXt+ikjYkWGqppp2pVwwgf4=
-----END CERTIFICATE-----`,
	}},
}

func TestNewFailure(t *testing.T) {
	TESTCASES := []struct {
		err string
		cfg signer.Configuration
	}{
		{err: "contentsignaturepki: invalid type", cfg: signer.Configuration{Type: ""}},
		{err: "contentsignaturepki: missing signer ID in signer configuration", cfg: signer.Configuration{Type: Type, ID: ""}},
		{err: "contentsignaturepki: missing private key in signer configuration", cfg: signer.Configuration{Type: Type, ID: "bob"}},
		{err: "contentsignaturepki: failed to get keys and rand for signer \"bob\"", cfg: signer.Configuration{Type: Type, ID: "bob", PrivateKey: "Ym9iCg=="}},
		{err: "contentsignaturepki: invalid public key type for issuer, must be ecdsa", cfg: signer.Configuration{
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
			t.Fatalf("expected to fail with '%s' but failed with '%s' instead", testcase.err, err)
		}
		if err == nil {
			t.Fatalf("expected to fail with '%v' but succeeded", testcase.err)
		}
	}
}

func TestMarshalUnfinished(t *testing.T) {
	var cs = &ContentSignature{
		Finished: false,
	}
	_, err := cs.Marshal()
	if err.Error() != "contentsignature.Marshal: unfinished cannot be encoded" {
		t.Fatalf("expected to fail with 'unfinished cannot be encoded' but got %v", err)
	}
}

func TestMarshalBadSigLen(t *testing.T) {
	var cs = &ContentSignature{
		Finished: true,
		Len:      1,
	}
	_, err := cs.Marshal()
	if err.Error() != "contentsignature.Marshal: invalid signature length 1" {
		t.Fatalf("expected to fail with 'invalid signature length' but got %v", err)
	}
}

func TestUnmarshalShortLen(t *testing.T) {
	_, err := Unmarshal("")
	if err.Error() != "contentsignature: signature cannot be shorter than 30 characters, got 0" {
		t.Fatalf("expected to fail with 'signature cannot be shorter than 30 characters', but got %v", err)
	}
}

func TestUnmarshalBadBase64(t *testing.T) {
	_, err := Unmarshal("gZimwQAsuCj_JcgxrIjw1wzON8WYN9YKp3I5I9NmOgnGLOJJwHDxjOA2QEnzN7bXBGWFgn8HJ7fGRYxBy1SHiDMiF8VX7V49KkanO9MO-RRN1AyC9xmghuEcF4ndhQaIgZimwQAsuCj_JcgxrIjw1wzON8WYN9YKp3I5I9NmOgnGLOJJwHDxjOA2QEnzN7bXBGWFgn8HJ7fGRYxBy1SHiDMiF8VX7V49KkanO9MO-RRN1AyC9xmghuEcF4ndhQaI")
	if err.Error() != "contentsignature: unknown signature length 192" {
		t.Fatalf("expected to fail with 'unknown signature length', but got %v", err)
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
	if err.Error() != "contentsignaturepki: refusing to sign input data shorter than 10 bytes" {
		t.Fatalf("expected to fail with input data too short but failed with: %v", err)
	}
}
