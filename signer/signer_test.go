// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package signer

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/miekg/pkcs11"
	"github.com/mozilla-services/autograph/crypto11"
	"github.com/mozilla-services/autograph/internal/mockpkcs11"
)

func TestParseRSAPrivateKey(t *testing.T) {
	_, err := ParsePrivateKey([]byte(rsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse RSA private key: %v", err)
	}
}

var rsaPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmDYP45RPsmV9qZbISn3tu3yplRJRuqJtF+Fu01Rc4aXGhAMD
NgyEmCGZsOxKG/g6GH5KmnE6V21Z7Iz45Q+xCnCGpFKJhugZxa0K9U9grqV7MtP7
2hF6Y9QPKaw7dHx/k3WwrPJe0Y/rKrGxImHjYKI4s0n2BrFdqntQq6AwC1zhXM+T
VNtGZpMwYfeEEZAXMjm7Goawy3qmUIBUbwSr9yKwbfuKRUCOZ8gQXiTL4VZ8xS8d
qJQBG4wx0VWEyaMoAolBERBJJnZWv6+phDen/1QGvlTcCFaYg9byrdI3KVOrKxqX
rKn7wKiaEWJpp/4OVcBhUegUhO8BSLegqliiAwIDAQABAoIBADVIh5tladjLiof5
jrf1CWnepAbZWN76yTHY6tDz8WfUfn/sBg2/qBMRgBndPbw40y2L2FXkWUYNs7MJ
Tn/xVEqRRbD0a8xcJ9l5UCK73N6Gc3BBoSKfh7a2n3A5KL8IbiiSxHxmhCbcOLjD
Z3zfw5cqcqrgs014fY+Wh5DtDKSNG5ODfYPqpZ/oMzLiwrlhgh2AqjRYDVbzPE/F
Q8Ab3xvS/dPTo42DDSR1ccHLCZCEOK/wAm+qxqd3dkbUQ5H4YFVI6Xp9WQaHKeZ1
xp8sdjQboMwHZ9YN4vWCNX3OrmfOzvN1F4wHdP0ptw+uY6Sbip0pDmQT3HHjrxve
rgj+xtECgYEA9dUtf5vRtTCN5GTxHT8Iz06uxWnn5+E3KHdudpWNx/YKITtImv5i
CuxhY1yESBgxfSojaV5QWPke4ma+qtN1tyRAjtF/k2WorjZsV9klMiXlAT63iPAG
abyOJ8deV3QIlYxSVhC0lAD+XfD5Rs+jBgWWayswZ+uA/8Ebm6PEgacCgYEAnoGj
5UPe23nvCMeCSdpnX3d/LfZnMkNenXt/rByN0a9vtjMEcZ5Sx1Tlv0roXGDtA3yv
xpgA8n4VDHvmvgpO5BK82TiA+1biUboHkF5sRYEJjsC2HtWQ0v6pl9xXTjecpSlC
eeFrsnWnSVhX9Z6V6e6B/EDkhp5LHPZk5bfm0EUCgYAYnFPmv5G6Avdhkx10YRgf
sO/cQaL+2tQrz/EWHBjKmP4gn4/APJFSKKIDUYLIuOtTbYGIDfIbRi1qWwDhlzPk
ttNjuON9vSKq9jXYgZuwroyDmGTFZ8oskbzljJcMSEiHuDmR9jAt1P+iJfq+tRDM
DIknh3ZcIP6UHCAIb9e/ZwKBgBbMKpiFBH6osPqgR1r78LZIZ6BiukD+c5NO+fP1
P2iTRQv9lnwI+3rz+P9kdLskrbI8ssNrhWdbPwfGok9fCC3BjCvp9pMv0elTSlc3
XXc5sfg4O3l/2g6e1iGjbWMwmHUg1BDXnTfTuDXSYQRQxNsalNOFOdkq1z7ZKXXo
12fJAoGBAOpDVpN70BSbBomI+wb+9Mx2GhLvPbKwhPEk9MaUGXGqxKjh0mDsMarR
WUElWLWSazm6kXPuqzyzDbJZRyKSHr9vH9AwlT8V/vQHebGz1CrErSd2Sv6ZIO5R
xYT2GfjxbFUqcnbLEKnjoccffVwxP6PONR9hzUXPIecMXfI3OOAU
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
		_, pub, err := testcase.cfg.MakeKey(keyTpl, "test")
		if err != nil {
			t.Fatalf("testcase %d failed to make %T key from signer configuration: %v", i, keyTpl, err)
		}
		keyTplType := fmt.Sprintf("%T", keyTpl)
		pubType := fmt.Sprintf("%T", pub)
		if keyTplType != pubType {
			t.Fatalf("testcase %d failed, expected public key of type %q but got %q", i, keyTplType, keyTplType)
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

func mockedPKCS11ContextFactory(ctx crypto11.PKCS11Context) crypto11.PKCS11ContextFactory {
	wrapped := func(_ *crypto11.PKCS11Config) (crypto11.PKCS11Context, error) {
		return ctx, nil
	}
	return wrapped
}

func TestMakeKeyAWSECDSA(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCtx := mockpkcs11.NewMockPKCS11Context(ctrl)
	defer ctrl.Finish()

	// we don't actually have any use for the private key besides extracting
	// the public key from it, but I couldn't find a way to directly construct
	// the public key.
	privKey, err := ParsePrivateKey([]byte(ecdsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	pubKey := privKey.(*ecdsa.PrivateKey).PublicKey

	// annoyingly, we also need the ecdh form of the private key
	// to find the length of it, to mock some things correctly.
	ecdhPrivKey, err := privKey.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		t.Fatalf("failed to convert ecdsa private key to ecdh: %v", err)
	}
	ecdhPubKey := ecdhPrivKey.PublicKey()

	// p256, prefix, and ecPointValue are all just intermediaries to set up
	// pubKeyAttrs, which is a return value needed by one of the mocks.
	p256, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatalf("failed to marshal p256 object identifier")
	}
	// nasty hack because i couldn't find any other way to make unmarshalEcPoint
	// happy.
	prefix := make([]byte, 2)
	prefix[0] = 0x04
	prefix[1] = byte(len(ecdhPubKey.Bytes()))
	ecPointValue := append(prefix, ecdhPubKey.Bytes()...)

	pubKeyAttrs := []*pkcs11.Attribute{
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_ECDSA_PARAMS,
			Value: p256,
		},
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_EC_POINT,
			Value: ecPointValue,
		},
	}

	label := "test"
	slot := uint(0)
	session := pkcs11.SessionHandle(0)
	object := pkcs11.ObjectHandle(0)
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)}
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, label),
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, p256),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, label),
	}

	mockCtx.EXPECT().Initialize().Return(nil).Times(1)
	mockCtx.EXPECT().GetSlotList(true).Return([]uint{slot}, nil).Times(3)
	mockCtx.EXPECT().GetTokenInfo(slot).Return(pkcs11.TokenInfo{}, nil).Times(1)
	mockCtx.EXPECT().OpenSession(slot, uint(6)).Return(session, nil).Times(1)
	mockCtx.EXPECT().GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate).Times(1)
	mockCtx.EXPECT().GetAttributeValue(session, object, attributeTemplate).Return(pubKeyAttrs, nil).Times(1)
	// these ones are called as part of Close(), not as part of our actual testing
	mockCtx.EXPECT().CloseSession(session).Return(nil).Times(1)
	mockCtx.EXPECT().CloseAllSessions(slot).Return(nil).Times(1)
	mockCtx.EXPECT().Finalize().Return(nil).Times(1)
	mockCtx.EXPECT().Destroy().Times(1)

	mockFactory := mockedPKCS11ContextFactory(mockCtx)
	crypto11.Configure(&crypto11.PKCS11Config{}, mockFactory)
	defer crypto11.Close()

	cfg := Configuration{
		isHsmAvailable: true,
		Hsm:            NewAWSHSM(mockCtx),
	}
	_, _, err = cfg.MakeKey(&pubKey, label)
	if err != nil {
		t.Fatalf("MakeKey failed: %v", err)
	}
}

func TestMakeKeyAWSRSA(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCtx := mockpkcs11.NewMockPKCS11Context(ctrl)
	defer ctrl.Finish()

	// we don't actually have any use for the private key besides extracting
	// the public key from it, but I couldn't find a way to directly construct
	// the public key.
	privKey, err := ParsePrivateKey([]byte(rsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	pubKey := privKey.(*rsa.PrivateKey).PublicKey

	pubKeyAttrs := []*pkcs11.Attribute{
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_MODULUS,
			Value: []byte("foo"),
		},
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_PUBLIC_EXPONENT,
			Value: []byte("foo"),
		},
	}

	label := "test"
	slot := uint(0)
	session := pkcs11.SessionHandle(0)
	object := pkcs11.ObjectHandle(0)
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, pubKey.Size()),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, label),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, label),
	}
	mockCtx.EXPECT().Initialize().Return(nil).Times(1)
	mockCtx.EXPECT().GetSlotList(true).Return([]uint{slot}, nil).Times(3)
	mockCtx.EXPECT().GetTokenInfo(slot).Return(pkcs11.TokenInfo{}, nil).Times(1)
	mockCtx.EXPECT().OpenSession(slot, uint(6)).Return(session, nil).Times(1)
	mockCtx.EXPECT().GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate).Times(1)
	mockCtx.EXPECT().GetAttributeValue(session, object, attributeTemplate).Return(pubKeyAttrs, nil).Times(1)
	// these ones are called as part of Close(), not as part of our actual testing
	mockCtx.EXPECT().CloseSession(session).Return(nil).Times(1)
	mockCtx.EXPECT().CloseAllSessions(slot).Return(nil).Times(1)
	mockCtx.EXPECT().Finalize().Return(nil).Times(1)
	mockCtx.EXPECT().Destroy().Times(1)

	mockFactory := mockedPKCS11ContextFactory(mockCtx)
	crypto11.Configure(&crypto11.PKCS11Config{}, mockFactory)
	defer crypto11.Close()
	cfg := Configuration{
		isHsmAvailable: true,
		Hsm:            NewAWSHSM(mockCtx),
	}
	_, _, err = cfg.MakeKey(&pubKey, label)
	if err != nil {
		t.Fatalf("MakeKey failed: %v", err)
	}
}

func TestMakeKeyGCPECDSA(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCtx := mockpkcs11.NewMockPKCS11Context(ctrl)
	defer ctrl.Finish()

	// we don't actually have any use for the private key besides extracting
	// the public key from it, but I couldn't find a way to directly construct
	// the public key.
	privKey, err := ParsePrivateKey([]byte(ecdsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	pubKey := privKey.(*ecdsa.PrivateKey).PublicKey

	// annoyingly, we also need the ecdh form of the private key
	// to find the length of it, to mock some things correctly.
	ecdhPrivKey, err := privKey.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		t.Fatalf("failed to convert ecdsa private key to ecdh: %v", err)
	}
	ecdhPubKey := ecdhPrivKey.PublicKey()

	// p256, prefix, and ecPointValue are all just intermediaries to set up
	// pubKeyAttrs, which is a return value needed by one of the mocks.
	p256, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatalf("failed to marshal p256 object identifier")
	}
	// nasty hack because i couldn't find any other way to make unmarshalEcPoint
	// happy.
	prefix := make([]byte, 2)
	prefix[0] = 0x04
	prefix[1] = byte(len(ecdhPubKey.Bytes()))
	ecPointValue := append(prefix, ecdhPubKey.Bytes()...)

	pubKeyAttrs := []*pkcs11.Attribute{
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_ECDSA_PARAMS,
			Value: p256,
		},
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_EC_POINT,
			Value: ecPointValue,
		},
	}

	label := "test"
	slot := uint(0)
	session := pkcs11.SessionHandle(0)
	object := pkcs11.ObjectHandle(0)
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)}
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}

	publicKeyTemplate := []*pkcs11.Attribute{}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_EC_SIGN_P256_SHA256),
	}

	mockCtx.EXPECT().Initialize().Return(nil).Times(1)
	mockCtx.EXPECT().GetSlotList(true).Return([]uint{slot}, nil).Times(3)
	mockCtx.EXPECT().GetTokenInfo(slot).Return(pkcs11.TokenInfo{}, nil).Times(1)
	mockCtx.EXPECT().OpenSession(slot, uint(6)).Return(session, nil).Times(1)
	mockCtx.EXPECT().GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate).Times(1)
	mockCtx.EXPECT().GetAttributeValue(session, object, attributeTemplate).Return(pubKeyAttrs, nil).Times(1)
	// these ones are called as part of Close(), not as part of our actual testing
	mockCtx.EXPECT().CloseSession(session).Return(nil).Times(1)
	mockCtx.EXPECT().CloseAllSessions(slot).Return(nil).Times(1)
	mockCtx.EXPECT().Finalize().Return(nil).Times(1)
	mockCtx.EXPECT().Destroy().Times(1)

	mockFactory := mockedPKCS11ContextFactory(mockCtx)
	crypto11.Configure(&crypto11.PKCS11Config{}, mockFactory)
	defer crypto11.Close()

	cfg := Configuration{
		isHsmAvailable: true,
		Hsm:            NewGCPHSM(mockCtx),
	}
	_, _, err = cfg.MakeKey(&pubKey, label)
	if err != nil {
		t.Fatalf("MakeKey failed: %v", err)
	}
}

func TestMakeKeyGCPRSA(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockCtx := mockpkcs11.NewMockPKCS11Context(ctrl)
	defer ctrl.Finish()

	// we don't actually have any use for the private key besides extracting
	// the public key from it, but I couldn't find a way to directly construct
	// the public key.
	privKey, err := ParsePrivateKey([]byte(rsaPrivateKey))
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	pubKey := privKey.(*rsa.PrivateKey).PublicKey

	pubKeyAttrs := []*pkcs11.Attribute{
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_MODULUS,
			Value: []byte("foo"),
		},
		&pkcs11.Attribute{
			Type:  pkcs11.CKA_PUBLIC_EXPONENT,
			Value: []byte("foo"),
		},
	}

	label := "test"
	slot := uint(0)
	session := pkcs11.SessionHandle(0)
	object := pkcs11.ObjectHandle(0)
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	attributeTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	publicKeyTemplate := []*pkcs11.Attribute{}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256),
	}
	mockCtx.EXPECT().Initialize().Return(nil).Times(1)
	mockCtx.EXPECT().GetSlotList(true).Return([]uint{slot}, nil).Times(3)
	mockCtx.EXPECT().GetTokenInfo(slot).Return(pkcs11.TokenInfo{}, nil).Times(1)
	mockCtx.EXPECT().OpenSession(slot, uint(6)).Return(session, nil).Times(1)
	mockCtx.EXPECT().GenerateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate).Times(1)
	mockCtx.EXPECT().GetAttributeValue(session, object, attributeTemplate).Return(pubKeyAttrs, nil).Times(1)
	// these ones are called as part of Close(), not as part of our actual testing
	mockCtx.EXPECT().CloseSession(session).Return(nil).Times(1)
	mockCtx.EXPECT().CloseAllSessions(slot).Return(nil).Times(1)
	mockCtx.EXPECT().Finalize().Return(nil).Times(1)
	mockCtx.EXPECT().Destroy().Times(1)

	mockFactory := mockedPKCS11ContextFactory(mockCtx)
	crypto11.Configure(&crypto11.PKCS11Config{}, mockFactory)
	defer crypto11.Close()
	cfg := Configuration{
		isHsmAvailable: true,
		Hsm:            NewGCPHSM(mockCtx),
	}
	_, _, err = cfg.MakeKey(&pubKey, label)
	if err != nil {
		t.Fatalf("MakeKey failed: %v", err)
	}
}
