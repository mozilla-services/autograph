// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package signer

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
)

func TestParseRSAPrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(rsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse RSA private key: %v", err)
	}
}

var rsaPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
`

func TestParseRSAPKCS8PrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(rsaPKCS8PrivateKey))
	if err != nil {
		t.Fatalf("failed to parse RSA private key: %v", err)
	}
}

var rsaPKCS8PrivateKey = `
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA2mn/+rpgWJTtE0dR
1hXNmoVJyXkZuq2VKQnjwjQix+EWd+Qd0QUJOlihRjQjhYss5IEpE4rH80Z+4lC/
ZPlTrQIDAQABAkEAqEHWgBnKFRONWzerFKixPmOGB15ycrw8V2QWAErXrHAOJkw5
EXtSkHmZFkB7nAvEF4yf+qvOTvc9qRWzP3aBJQIhAPv5ODWQUn2FBWvPN6CVpnTP
41fsbfxVLxKzRFZPZnAHAiEA3ed+kGAc7AAQpi4hAWAMZA3HFDcXUGxQyc+c1xHx
yasCIQC1XF1D2Hw3Uj5jqcONNwmXfGZTS56ih6GZISTnxsChkwIgCBenH/DBXUHr
WYQZJAmyqftupSgVK5OnppRxrc4zuR0CIAwEykI9Y0WuMR7p+8VHPCMOj2dnOwq2
lC+fVp5q9huB
-----END PRIVATE KEY-----
`

func TestParseECDSAPrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(ecdsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse ECDSA private key: %v", err)
	}
}

var ecdsaPrivateKey = `
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEII+Is30aP9wrB/H6AkKrJjMG8EVY2WseSFHTfWGCIk7voAoGCCqGSM49
AwEHoUQDQgAEMdzAsqkWQiP8Fo89qTleJcuEjBtp2c6z16sC7BAS5KXvUGghURYq
3utZw8En6Ik/4Om8c7EW/+EO+EkHShhgdA==
-----END EC PRIVATE KEY-----
`

func TestParseECDSAPKCS8PrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(ecdsaPKCS8PrivateKey))
	if err != nil {
		t.Fatalf("failed to parse ECDSA private key: %v", err)
	}
}

var ecdsaPKCS8PrivateKey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyptBhPFj+HwVUdqL
oaVpy+m3JSqdFz+PGendvt87giOhRANCAATFbsFduWWidi3wZ2ZFXbLj3Rb3kLny
Uk7hsSrmYvDod8D71KCWhZAV1otVxjDUwCvmRoozqSl4EtzKdTWvWeDY
-----END PRIVATE KEY-----
`

func TestParseInvalidPrivateKey(t *testing.T) {
	var TESTCASES = []struct {
		name string
		pkey []byte
	}{
		{"empty private key", []byte(``)},

		{"certificate", []byte(`
-----BEGIN CERTIFICATE-----
MIICxTCCAmugAwIBAgIJAOVr07yMf6huMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTcwNjEzMTQwMzQ0WhcNMTkwNjEzMTQwMzQ0WjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZI
zj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////MFsEIP////8A
AAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0G
sMxTsPY7zjw+J9JgSwMVAMSdNgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4
vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7L
tkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IA
BEyYkrzxDUJan7r2T6H+yOMmqbpNSFJAFQg66Xzknb4+rrx/e0j8cAecMQZfOq5s
kswFPQ9u+YXoJr+SLRavTMKjUDBOMB0GA1UdDgQWBBQkKZzE8sgvxJPq5i9nh03G
CcZjuTAfBgNVHSMEGDAWgBQkKZzE8sgvxJPq5i9nh03GCcZjuTAMBgNVHRMEBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQD6+Hys0Tu7U3HUzwO9NJ4ElU70D4rbyaPU
TH3zjxA6+gIgM0uXspkAbNgyO0qYkOQeoIfIXTan0uqt7b5PbLcGlh8=
-----END CERTIFICATE----`)},
		// we cannot parse DSA keys in PKCS1 format
		{"dsa pkcs1 private key", []byte(`
-----BEGIN DSA PRIVATE KEY-----
MIH6AgEAAkEA5Kz55zU3Yk1rgLsZvBNrkFZs1++7JcuMFGSfH3gkwiAeHo+5ztHy
WD8P45cvxOTR4ouLMeCdwrAohlnF9+D39QIVAJ7QMH/ewcC0UBkjEb/G03cx9drn
AkEA2d97oKn6wdNrHJWRTlmZl0OOBmjWmNnGgONfGNdbycNNRmj++eB2/YBnmGX/
iqP4h6Z58t45o4dVbUIvtcXxkQJBALP5X9dHxQeY53HTpkb3dDQdtjOadU6ik86l
O1xhS+jXsaR+8bXu5ImcgivKkpDYGX048p4mR654t09GWkohT7ICFQCD0UuihlMV
6XHJyV+/G2aUJJlCwA==
-----END DSA PRIVATE KEY-----`)},
		// we will not parse DSA keys in PKCS8 format
		{"dsa pkcs8 private key", []byte(`
------BEGIN PRIVATE KEY-----
-MIHIAgEAMIGpBgcqhkjOOAQBMIGdAkEA5Kz55zU3Yk1rgLsZvBNrkFZs1++7JcuM
-FGSfH3gkwiAeHo+5ztHyWD8P45cvxOTR4ouLMeCdwrAohlnF9+D39QIVAJ7QMH/e
-wcC0UBkjEb/G03cx9drnAkEA2d97oKn6wdNrHJWRTlmZl0OOBmjWmNnGgONfGNdb
-ycNNRmj++eB2/YBnmGX/iqP4h6Z58t45o4dVbUIvtcXxkQQXAhUAg9FLooZTFelx
-yclfvxtmlCSZQsA=
------END PRIVATE KEY-----`)},
	}
	for i, testcase := range TESTCASES {
		_, err := ParsePrivateKey(testcase.pkey)
		if err == nil {
			t.Fatalf("testcase %d should have failed to parse %q but succeeded", i, testcase.name)
		}
	}
}

func TestParseEmptyPrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(``))
	if err == nil {
		t.Fatalf("should have failed to parse empty private key but succeeded")
	}
}

func TestInitHSM(t *testing.T) {
	tcfg := new(Configuration)
	tcfg.InitHSM(nil)
	if !tcfg.isHsmAvailable {
		t.Fatal("expected isHsmAvailable to be set to true but still false")
	}
}

func TestGetPrivateKey(t *testing.T) {
	tcfg := new(Configuration)
	tcfg.PrivateKey = rsaPrivateKey
	key, err := tcfg.GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("expected private key but got nil")
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		break
	default:
		t.Fatalf("expected rsa private key but got %T", key)
	}
}

func TestHSMNotAvailable(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("HSM search did not panic but should have")
		}
	}()
	tcfg := new(Configuration)
	tcfg.InitHSM(nil)
	tcfg.GetPrivateKey()
}

func TestNoSuitableKeyFound(t *testing.T) {
	tcfg := new(Configuration)
	_, err := tcfg.GetPrivateKey()
	if err == nil {
		t.Fatal("expected to fail with no suitable key found but succeeded")
	}
	if err.Error() != "no suitable key found" {
		t.Fatalf("expected to fail with no suitable key found but failed with: %v", err)
	}
}

func TestMakeKey(t *testing.T) {
	for i, testcase := range PASSINGTESTCASES {
		_, keyTpl, _, err := testcase.cfg.GetKeys()
		if err != nil {
			t.Fatalf("testcase %d failed to load signer configuration: %v", i, err)
		}
		priv, pub, err := testcase.cfg.MakeKey(keyTpl, "test")
		if err != nil {
			t.Fatalf("testcase %d failed to make %T key from signer configuration: %v", i, keyTpl, err)
		}
		keyTplType := fmt.Sprintf("%T", keyTpl)
		pubType := fmt.Sprintf("%T", pub)
		if keyTplType != pubType {
			t.Fatalf("testcase %d failed, expected public key of type %q but got %q", i, keyTplType, keyTplType)
		}
		if GetPrivKeyHandle(priv) != 0 {
			t.Fatalf("testcase %d failed, expected public key handle 0 but got %d", i, GetPrivKeyHandle(priv))
		}
	}
}

var PASSINGTESTCASES = []struct {
	cfg Configuration
}{
	{cfg: Configuration{
		//p-384
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDNUOCI9Jxy+v8f/aB5IWIY8A2IdMMEkbR0qTwPpoktAlZvci1e/5/S
1zV5TLA5SkKgBwYFK4EEACKhZANiAASi4qvgd/865yGf6yzg9J+LSt/TsbtxH4+K
twf3ayo9dfTh8J47RIkJqmonF8oiCrecjHMsjCNzR+74HFKlK7zFZKcXg+Me2djq
wTLpwBkQetKDa4mvSLxBNlUH9mLW2l8=
-----END EC PRIVATE KEY-----`,
	}},
	{cfg: Configuration{
		// p-256
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
	{cfg: Configuration{
		PrivateKey: `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDYU0DX8fqlyaJqha6D0DvHAtde8o3xIxXYX8ONwVbUIJMur+42
rsXZk8vQkeSzQ9evIAlara5X9aSvCo0O4Lg7VzHjRd5Ip2RwWAknJY942XCBF+CO
M9NTwjQRlBjNrRK9Qm3gRHLkCsw5mqDkzXXPkKXw5jeiveAsQIES40YgIwIDAQAB
AoGAESQfqjzRWJuuk/Q9zNIOOom+GRbtKmNWUsvbyfq875gZMYTdQlX89W2ho8g7
r/y7NXQ7aYUDoJKlVv1mCfzCfEPsl+AppNzRWf7Dsvgv4OHLCMP6pzliSWz+Teh3
eybe17v8OtmrWWRZpf+mBdIBZ1AUFh9ET9hHsil5I7s2VjkCQQD049sKsFdltnqJ
nfkFhyxWomNhmY4f37iUOl562gcP71Dqg+IeB7mTaqxc2KwErZYPb0H+ov8NxNLJ
GPva6FB1AkEA4iOlgES3aIPeoYYoqKRrYxx4kOO0s2cRxlEbt+nbDgdxIjsxeS29
Fz/p9GCsutHrpAwIBDNrgmG5V0yfE06bNwJBAI7hBmLFIijQ/8udJLaJ+F+PnUZL
jjWglRO+vnMVFDvC2EYLrnjw7uBIw8nkDPEpyjy1IB8OQJtq88Sq0/8TviUCQH0s
Jgvd/XeIps7Zp9/RQu/Vbpcks30qbBhOBP3EIFCfpevAwB3HR4d7BVETwgiW8cwY
LMfGfpfo5+J+sv7I3/kCQEvkxSGguHckNzqV7nZgwskbFfvTVLqMaPy9EVfu2od+
ZkJ9hRz+l4ZVOsgNPHXPEi0AXWnDV6zrRQBpDYyiGhY=
-----END RSA PRIVATE KEY-----`,
	}},
}

func TestAcceptedFilenames(t *testing.T) {
	for _, testcase := range acceptedFileNames {
		err := isValidUnsignedFilename(testcase)
		if err != nil {
			t.Fatalf("failed to accept: %s reason: %v", testcase, err)
		}
	}
}

func TestRejectedFilenames(t *testing.T) {
	for _, testcase := range rejectedFileNames {
		err := isValidUnsignedFilename(testcase)
		if err == nil {
			t.Fatalf("failed to reject: %s", testcase)
		}
	}
}

var acceptedFileNames = []string{
	"simple.txt",
	"example_1.2.3-456.dsc",
	"complex-example123_4.5a.7~alpha1.buildinfo",
	"complex+example456_6.a6.6~beta2+fix3.changes",
}

var rejectedFileNames = []string{
	".dotfile",
	"~tempfile",
	"tempfile~",
	"abcdef..xyz",
	"control!chars",
	"control@chars",
	"control#chars",
	"control$chars",
	"control%%chars",
	"control^chars",
	"control*chars",
	"_non_alpha_start",
}

func TestSanitizedConfig(t *testing.T) {
	for _, testcase := range sanitizerTestCases {
		r := testcase.cfg.Sanitize()
		if testcase.result != *r {
			expect, _ := json.MarshalIndent(testcase.result, "", "  ")
			actual, _ := json.MarshalIndent(r, "", "  ")
			t.Logf("expected: %s", expect)
			t.Logf("actual: %s", actual)
			t.Fatalf("Sanitized config failed for: %s", testcase.cfg.ID)
		}
	}
}

var sanitizerTestCases = []struct {
	cfg    Configuration
	result SanitizedConfig
}{
	// All the fields are copied over.
	{cfg: Configuration{
		ID:                  "copy-public-values",
		Type:                "bar",
		Mode:                "qux",
		PublicKey:           "This is a public key",
		IssuerCert:          "This is an issuer",
		Certificate:         "This is a certificate",
		X5U:                 "http://example.com/",
		KeyID:               "This is a keyid",
		SubdomainOverride:   "allizom.com",
		Validity:            12345,
		ClockSkewTolerance:  555,
		ChainUploadLocation: "file:///somewhere/over/the/rainbow",
		CaCert:              "The root of evil",
		Hash:                "sha666",
		SaltLength:          9001,
	},
		result: SanitizedConfig{
			ID:                  "copy-public-values",
			Type:                "bar",
			Mode:                "qux",
			PublicKey:           "This is a public key",
			IssuerCert:          "This is an issuer",
			Certificate:         "This is a certificate",
			X5U:                 "http://example.com/",
			KeyID:               "This is a keyid",
			SubdomainOverride:   "allizom.com",
			Validity:            12345,
			ClockSkewTolerance:  555,
			ChainUploadLocation: "file:///somewhere/over/the/rainbow",
			CaCert:              "The root of evil",
			Hash:                "sha666",
			SaltLength:          9001,
		}},
	// Private keys are hashed with SHA256
	{cfg: Configuration{
		ID:            "private-key-example",
		PrivateKey:    "hello world",
		IssuerPrivKey: "Lorem Ipsum",
	},
		result: SanitizedConfig{
			ID: "private-key-example",
			// echo -n "hello world" | sha256sum
			PrivateKey: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			// echo -n "Lorem Ipsum" | sha256sum
			IssuerPrivKey: "030dc1f936c3415aff3f3357163515190d347a28e758e1f717d17bae453541c9",
		}},
	// Certificates should parse out the fingerprint and validity dates.
	{cfg: Configuration{
		ID: "cert-extra-data",
		Certificate: `
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
	},
		result: SanitizedConfig{
			ID: "cert-extra-data",
			Certificate: `
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
			// openssl x509 -outform DER | shasum
			CertFingerprintSha1: "793a92cb335c3846ffed7f8c112137cd8a75e7c7",
			// openssl x509 -outform DER | sha256sum
			CertFingerprintSha256: "61bd2500b732d2889a1b17c24365741550534fb715cd4f7c463a23a35bd931ee",
			// openssl x509 -noout -text
			CertDateStart: "2018-12-21T15:56:46Z",
			CertDateEnd:   "2029-02-22T15:56:46Z",
		}},
}
