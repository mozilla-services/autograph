// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package contentsignaturepki

import (
	"crypto/ecdsa"
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
		if s.Mode != testcase.cfg.Mode {
			t.Fatalf("testcase %d signer curve %q does not match expected %q", i, s.Mode, testcase.cfg.Mode)
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

		// verify the signature using the public key of the end entity
		_, certs, err := GetX5U(buildHTTPClient(), s.X5U)
		if err != nil {
			t.Fatalf("testcase %d failed to get X5U %q: %v", i, s.X5U, err)
		}
		leaf := certs[0]
		key := leaf.PublicKey.(*ecdsa.PublicKey)
		if !sig.(*verifier.ContentSignature).VerifyData([]byte(input), key) {
			t.Fatalf("testcase %d failed to verify signature", i)
		}

		if leaf.Subject.CommonName != testcase.expectedCommonName {
			t.Errorf("testcase %d expected common name %#v, got %#v", i, testcase.expectedCommonName, leaf.Subject.CommonName)
		}
	}
}

var PASSINGTESTCASES = []struct {
	cfg                signer.Configuration
	expectedCommonName string
}{
	{cfg: signer.Configuration{
		Type:                Type,
		ID:                  "testsigner0",
		Mode:                P384ECDSA,
		X5U:                 "file:///tmp/autograph_unit_tests/chains/",
		ChainUploadLocation: "file:///tmp/autograph_unit_tests/chains/",
		IssuerPrivKey: `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBcwxsHPTSHIVY1qLobCqBtnjRe0UZWOro1xtg2oV4rkypbkkgHHnSA
s8p0PlGIknKgBwYFK4EEACKhZANiAAQMBfcDj4r/9aAXcUsjjun3vCpBSQoskcdi
iF4bE+AcFmPABh6AnwTZv0sHYPjkovk3R3RfuXlKyoqhuD73VqBhkuK7R6mN2snh
fRkWmi6SzHWZIXPzFScoCaHnJrFzNjs=
-----END EC PRIVATE KEY-----`,
		IssuerCert: `
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
	},
		expectedCommonName: "testsigner0.content-signature.mozilla.org",
	},
	{cfg: signer.Configuration{
		Type:                Type,
		ID:                  "testsigner1",
		Mode:                P256ECDSA,
		X5U:                 "file:///tmp/autograph_unit_tests/chains/",
		ChainUploadLocation: "file:///tmp/autograph_unit_tests/chains/",
		IssuerPrivKey: `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEABir6WMfkbG2ZyKKDCij1PlSBldaaJqPQ/9ioWvCM5oAoGCCqGSM49
AwEHoUQDQgAED0x4GeyH3nxaCVQqPFbRkoBg1BJePxTSg1oaRWIgBbrMYaB/TKpL
WoBQZFUwn11IFDP5y1B6Tt9U5DxQ3tgt+w==
-----END EC PRIVATE KEY-----`,
		IssuerCert: `
-----BEGIN CERTIFICATE-----
MIICIDCCAcWgAwIBAgIIFYW+N1jIJvAwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODU0NzkxMB4XDTE4MTIyMTE2
NTk1MVoXDTI5MDIyMjE2NTk1MVowYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
VQQDExFjc2ludGVyMTU1MDg1NDc5MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BA9MeBnsh958WglUKjxW0ZKAYNQSXj8U0oNaGkViIAW6zGGgf0yqS1qAUGRVMJ9d
SBQz+ctQek7fVOQ8UN7YLfujajBoMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
BggrBgEFBQcDAzAPBgNVHRMBAf8EBTADAQH/MDAGA1UdHgEB/wQmMCSgIjAggh4u
Y29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMDSQAwRgIh
AJYQbM1zDA9RkmNwEc4LafBwL98Z+aGy31z80HeC5Y8hAiEA4KEG+ZNinz5yZItW
NYDcA5Hvd1xXeRQi6SWj6Z2qT7w=
-----END CERTIFICATE-----`,
		CaCert: `
-----BEGIN CERTIFICATE-----
MIIB7DCCAZKgAwIBAgIIFYW+N1i+RHgwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODU0NzkxMB4XDTE4MTIyMDE2
NTk1MVoXDTQ5MDIyMjE2NTk1MVowXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRkwFwYD
VQQDExBjc3Jvb3QxNTUwODU0NzkxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
SZakSnBD3qkp15bQ+qzcKCn2+OmoOJKVgrSezyrx7IHjtEbCYUz8Zp+HhKg3NXLY
6ZMjO0zYnq3gTdAzH3amOqM4MDYwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
CCsGAQUFBwMDMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDSAAwRQIgIBgf
KkmH7TerRPn/517v/41o/sF9Hd9iGBilyWtVMggCIQClvRXiMM6DrabvybPGHWTt
mpvOMOT3falDgXh0iOgdIA==
-----END CERTIFICATE-----`,
	},
		expectedCommonName: "testsigner1.content-signature.mozilla.org",
	},
	{cfg: signer.Configuration{
		Type:                Type,
		ID:                  "testsigner1",
		SubdomainOverride:   "anothersigner1",
		Mode:                P256ECDSA,
		X5U:                 "file:///tmp/autograph_unit_tests/chains/dedup-path-anothersigner1",
		ChainUploadLocation: "file:///tmp/autograph_unit_tests/chains/dedup-path-anothersigner1",
		IssuerPrivKey: `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEABir6WMfkbG2ZyKKDCij1PlSBldaaJqPQ/9ioWvCM5oAoGCCqGSM49
AwEHoUQDQgAED0x4GeyH3nxaCVQqPFbRkoBg1BJePxTSg1oaRWIgBbrMYaB/TKpL
WoBQZFUwn11IFDP5y1B6Tt9U5DxQ3tgt+w==
-----END EC PRIVATE KEY-----`,
		IssuerCert: `
-----BEGIN CERTIFICATE-----
MIICIDCCAcWgAwIBAgIIFYW+N1jIJvAwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODU0NzkxMB4XDTE4MTIyMTE2
NTk1MVoXDTI5MDIyMjE2NTk1MVowYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
VQQDExFjc2ludGVyMTU1MDg1NDc5MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BA9MeBnsh958WglUKjxW0ZKAYNQSXj8U0oNaGkViIAW6zGGgf0yqS1qAUGRVMJ9d
SBQz+ctQek7fVOQ8UN7YLfujajBoMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
BggrBgEFBQcDAzAPBgNVHRMBAf8EBTADAQH/MDAGA1UdHgEB/wQmMCSgIjAggh4u
Y29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMDSQAwRgIh
AJYQbM1zDA9RkmNwEc4LafBwL98Z+aGy31z80HeC5Y8hAiEA4KEG+ZNinz5yZItW
NYDcA5Hvd1xXeRQi6SWj6Z2qT7w=
-----END CERTIFICATE-----`,
		CaCert: `
-----BEGIN CERTIFICATE-----
MIIB7DCCAZKgAwIBAgIIFYW+N1i+RHgwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODU0NzkxMB4XDTE4MTIyMDE2
NTk1MVoXDTQ5MDIyMjE2NTk1MVowXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRkwFwYD
VQQDExBjc3Jvb3QxNTUwODU0NzkxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
SZakSnBD3qkp15bQ+qzcKCn2+OmoOJKVgrSezyrx7IHjtEbCYUz8Zp+HhKg3NXLY
6ZMjO0zYnq3gTdAzH3amOqM4MDYwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
CCsGAQUFBwMDMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDSAAwRQIgIBgf
KkmH7TerRPn/517v/41o/sF9Hd9iGBilyWtVMggCIQClvRXiMM6DrabvybPGHWTt
mpvOMOT3falDgXh0iOgdIA==
-----END CERTIFICATE-----`,
	},
		expectedCommonName: "anothersigner1.content-signature.mozilla.org",
	},
}

func TestNewFailure(t *testing.T) {
	TESTCASES := []struct {
		err string
		cfg signer.Configuration
	}{
		{err: `contentsignaturepki "": invalid type`, cfg: signer.Configuration{Type: ""}},
		{err: `contentsignaturepki "": missing signer ID in signer configuration`, cfg: signer.Configuration{Type: Type, ID: ""}},
		{err: `contentsignaturepki "bob": missing issuer private key in signer configuration`, cfg: signer.Configuration{Type: Type, ID: "bob"}},
		{err: `contentsignaturepki "bob": failed to get keys`, cfg: signer.Configuration{Type: Type, ID: "bob", IssuerPrivKey: "Ym9iCg=="}},
		{err: `contentsignaturepki "abcd": invalid public key type for issuer, must be ecdsa`, cfg: signer.Configuration{
			Type: Type,
			ID:   "abcd",
			IssuerPrivKey: `
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

func TestNoShortData(t *testing.T) {
	s, err := New(PASSINGTESTCASES[0].cfg)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	_, err = s.SignData([]byte("a"), nil)
	if err == nil {
		t.Fatal("expected to fail with input data too short but succeeded")
	}
	if err.Error() != `contentsignaturepki "testsigner0": refusing to sign input data shorter than 10 bytes` {
		t.Fatalf("expected to fail with input data too short but failed with: %v", err)
	}
}
