// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package signer

import (
	"crypto/rsa"
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

func TestParseDSAPKCS8PrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(dsaPKCS8PrivateKey))
	if err != nil {
		t.Fatalf("failed to parse DSA private key: %v", err)
	}
}

var dsaPKCS8PrivateKey = `
-----BEGIN PRIVATE KEY-----
MIHIAgEAMIGpBgcqhkjOOAQBMIGdAkEA5Kz55zU3Yk1rgLsZvBNrkFZs1++7JcuM
FGSfH3gkwiAeHo+5ztHyWD8P45cvxOTR4ouLMeCdwrAohlnF9+D39QIVAJ7QMH/e
wcC0UBkjEb/G03cx9drnAkEA2d97oKn6wdNrHJWRTlmZl0OOBmjWmNnGgONfGNdb
ycNNRmj++eB2/YBnmGX/iqP4h6Z58t45o4dVbUIvtcXxkQQXAhUAg9FLooZTFelx
yclfvxtmlCSZQsA=
-----END PRIVATE KEY-----`

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
		// we can parse DSA keys in PKCS8 format, but not in PKCS1
		{"dsa pkcs1 private key", []byte(`
-----BEGIN DSA PRIVATE KEY-----
MIH6AgEAAkEA5Kz55zU3Yk1rgLsZvBNrkFZs1++7JcuMFGSfH3gkwiAeHo+5ztHy
WD8P45cvxOTR4ouLMeCdwrAohlnF9+D39QIVAJ7QMH/ewcC0UBkjEb/G03cx9drn
AkEA2d97oKn6wdNrHJWRTlmZl0OOBmjWmNnGgONfGNdbycNNRmj++eB2/YBnmGX/
iqP4h6Z58t45o4dVbUIvtcXxkQJBALP5X9dHxQeY53HTpkb3dDQdtjOadU6ik86l
O1xhS+jXsaR+8bXu5ImcgivKkpDYGX048p4mR654t09GWkohT7ICFQCD0UuihlMV
6XHJyV+/G2aUJJlCwA==
-----END DSA PRIVATE KEY-----`)},
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

func TestEnableHSM(t *testing.T) {
	tcfg := new(Configuration)
	tcfg.HSMIsAvailable()
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
	tcfg.HSMIsAvailable()
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
