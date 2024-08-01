package xpi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/mozilla-services/autograph/signer"
	"go.mozilla.org/pkcs7"
)

func TestSignFile(t *testing.T) {
	t.Parallel()

	inputs := []struct {
		name    string
		content []byte
	}{
		{
			name:    "unsigned_bootstrap_2.xpi",
			content: unsignedBootstrap,
		},
		{
			name:    "ublock_origin-1.33.2-an+fx.xpi",
			content: ublockOrigin,
		},
		{
			name:    "omni.ja.zip",
			content: fxOmnija,
		},
		{
			name:    "browser/omni.ja.zip",
			content: fxBrowserOmnija,
		},
	}

	for i, testcase := range validSignerConfigs {
		for _, input := range inputs {
			inputBytes := input.content
			t.Run(fmt.Sprintf("test sign file %s signer id %s (%d)", input.name, testcase.ID, i), func(t *testing.T) {
				t.Parallel()

				statsdClient, err := statsd.NewBuffered("localhost:8135", 1)
				if err != nil {
					t.Fatalf("passing testcase %d: Error constructing statsdClient: %v", i, err)
				}
				statsdClient.Namespace = "test_autograph_stats_ns"
				signerStatsClient, err := signer.NewStatsClient(testcase, statsdClient)
				if err != nil {
					t.Fatalf("passing testcase %d: Error constructing signer.StatsdClient: %v", i, err)
				}

				s, err := New(testcase, signerStatsClient)
				if err != nil {
					t.Fatalf("passing testcase %d: signer initialization failed with: %v", i, err)
				}
				if s.Config().Type != testcase.Type {
					t.Fatalf("passing testcase %d: signer type %q does not match configuration %q", i, s.Config().Type, testcase.Type)
				}
				if s.Config().ID != testcase.ID {
					t.Fatalf("passing testcase %d: signer id %q does not match configuration %q", i, s.Config().ID, testcase.ID)
				}
				if s.Config().PrivateKey != testcase.PrivateKey {
					t.Fatalf("passing testcase %d: signer private key %q does not match configuration %q", i, s.Config().PrivateKey, testcase.PrivateKey)
				}
				if s.Config().Mode != testcase.Mode {
					t.Fatalf("passing testcase %d: signer category %q does not match configuration %q", i, s.Config().Mode, testcase.Mode)
				}

				// sign input data
				opts := s.GetDefaultOptions().(Options)
				if testcase.Mode == ModeAddOnWithRecommendation {
					opts.Recommendations = []string{"recommended"}
				}
				signedXPI, err := s.SignFile(inputBytes, opts)
				if err != nil {
					t.Fatalf("passing testcase %d %s: failed to sign file with detached PKCS7 sig: %v", i, testcase.ID, err)
				}

				err = VerifySignedFile(signedXPI, nil, opts, time.Now().UTC())
				if err != nil {
					t.Fatalf("passing testcase %d: failed to verify PKCS7 signed file: %v", i, err)
				}
			})
		}
	}
}

func TestSignData(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	for i, testcase := range validSignerConfigs {
		t.Run(fmt.Sprintf("test sign data signer id %s (%d)", testcase.ID, i), func(t *testing.T) {
			t.Parallel()

			// initialize a signer
			s, err := New(testcase, nil)
			if err != nil {
				t.Fatalf("testcase %d signer initialization failed with: %v", i, err)
			}
			if s.Config().Type != testcase.Type {
				t.Fatalf("testcase %d signer type %q does not match configuration %q", i, s.Config().Type, testcase.Type)
			}
			if s.Config().ID != testcase.ID {
				t.Fatalf("testcase %d signer id %q does not match configuration %q", i, s.Config().ID, testcase.ID)
			}
			if s.Config().PrivateKey != testcase.PrivateKey {
				t.Fatalf("testcase %d signer private key %q does not match configuration %q", i, s.Config().PrivateKey, testcase.PrivateKey)
			}
			if s.Config().Mode != testcase.Mode {
				t.Fatalf("testcase %d signer category %q does not match configuration %q", i, s.Config().Mode, testcase.Mode)
			}

			// sign input data
			sig, err := s.SignData(input, s.GetDefaultOptions())
			if err != nil {
				t.Fatalf("testcase %d failed to sign data: %v", i, err)
			}
			// convert signature to string format
			sigstr, err := sig.Marshal()
			if err != nil {
				t.Fatalf("testcase %d failed to marshal signature: %v", i, err)
			}

			// convert string format back to signature
			sig2, err := Unmarshal(sigstr, input)
			if err != nil {
				t.Fatalf("testcase %d failed to unmarshal signature: %v", i, err)
			}

			// make sure we still have the same string representation
			sigstr2, err := sig2.Marshal()
			if err != nil {
				t.Fatalf("testcase %d failed to re-marshal signature: %v", i, err)
			}
			if sigstr != sigstr2 {
				t.Fatalf("testcase %d marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
					i, sigstr, sigstr2)
			}
			// verify signature on input data
			if sig2.VerifyWithChain(nil) != nil {
				t.Fatalf("testcase %d failed to verify xpi signature", i)
			}
		})
	}
}

func TestSignDataAndVerifyWithOpenSSL(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")

	// init a signer
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}

	// sign input data with bad option
	sig, err := s.SignData(input, struct{ ID string }{ID: "foo@bar.net"})
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}
	pkcs7Sig := sig.(*Signature).String()

	// write the signature to a temp file
	tmpSignatureFile, err := os.CreateTemp("", "TestSignDataAndVerifyWithOpenSSL_signature")
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(tmpSignatureFile.Name(), []byte(pkcs7Sig), 0755)
	if err != nil {
		t.Fatalf("error writing file %s: %q", tmpSignatureFile.Name(), err)
	}

	// write the input to a temp file
	tmpContentFile, err := os.CreateTemp("", "TestSignDataAndVerifyWithOpenSSL_input")
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(tmpContentFile.Name(), input, 0755)
	if err != nil {
		t.Fatal(err)
	}

	// write the issuer cert to a temp file
	tmpIssuerCertFile, err := os.CreateTemp("", "TestSignDataAndVerifyWithOpenSSL_issuer")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := os.OpenFile(tmpIssuerCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: s.issuerCert.Raw})
	fd.Close()

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "cms", "-verify", "-purpose", "any",
		"-in", tmpSignatureFile.Name(), "-inform", "PEM",
		"-content", tmpContentFile.Name(),
		"-CAfile", tmpIssuerCertFile.Name())
	out, err := opensslCMD.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to verify pkcs7 signature with openssl: %s\n%s", err, out)
	}
	t.Logf("OpenSSL PKCS7 signature verification output:\n%s\n", out)
	// clean up
	os.Remove(tmpSignatureFile.Name())
	os.Remove(tmpContentFile.Name())
	os.Remove(tmpIssuerCertFile.Name())
}

func verifyPKCS7DigestWithPKCS7Lib(t *testing.T, input, pkcs7Sig, testCaseCerts []byte) error {
	p7, err := pkcs7.Parse(pkcs7Sig)
	if err != nil {
		t.Fatalf("failed to parse XPI sig %q", err)
	}
	p7.Content = input

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(testCaseCerts)
	if !ok {
		t.Fatalf("failed to add root cert to pool")
	}
	return p7.VerifyWithChain(roots)
}

func TestSignDataWithPKCS7VerifiesDigests(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	testcase := validSignerConfigs[3]

	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}

	// NB: can't call SignData directly since it doesn't support SHA256
	pkcs7SigSHA2, err := s.signDataWithPKCS7(input, "foo@bar.net", pkcs7.OIDDigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("failed to sign XPI with SHA2 digest %q", err)
	}
	err = verifyPKCS7DigestWithPKCS7Lib(t, input, pkcs7SigSHA2, []byte(testcase.Certificate))
	if err != nil {
		t.Fatalf("failed to verify PKCS7 with SHA2 digest")
	}

	pkcs7SigSHA1, err := s.signDataWithPKCS7(input, "foo@bar.net", pkcs7.OIDDigestAlgorithmSHA1)
	if err != nil {
		t.Fatalf("failed to sign XPI with SHA1 digest %q", err)
	}
	err = verifyPKCS7DigestWithPKCS7Lib(t, input, pkcs7SigSHA1, []byte(testcase.Certificate))
	if err != nil {
		t.Fatalf("failed to verify PKCS7 with SHA1 digest")
	}

	_, err = s.signDataWithPKCS7(input, "foo@bar.net", nil)
	if err == nil {
		t.Fatalf("signing XPI with nil digest did not error")
	}
}

func TestNewFailure(t *testing.T) {
	t.Parallel()

	for i, testcase := range invalidSignerConfigs {
		_, err := New(testcase.cfg, nil)
		// check for lack of error first, otherwise `err.Error()` will cause a panic if no error
		// is present.
		if err == nil {
			t.Fatalf("testcase %d expected to fail with '%v' but succeeded", i, testcase.err)
		} else if !strings.Contains(err.Error(), testcase.err) {
			t.Fatalf("testcase %d expected to fail with '%v' but failed with '%v' instead", i, testcase.err, err)
		}
	}
}

func TestOptionsP7Digest(t *testing.T) {
	t.Parallel()

	testcase := validSignerConfigs[3]
	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	opts := s.GetDefaultOptions().(Options)

	opts.PKCS7Digest = "SHA256"
	digest, err := opts.PK7Digest()
	if err != nil {
		t.Fatalf("PK7Digest() returned unexpected error %q", err)
	}
	if !digest.Equal(pkcs7.OIDDigestAlgorithmSHA256) {
		t.Fatalf("PK7Digest() returned unexpected digest %q", digest)
	}

	opts.PKCS7Digest = "sha1"
	digest, err = opts.PK7Digest()
	if err != nil {
		t.Fatalf("PK7Digest() returned unexpected error %q", err)
	}
	if !digest.Equal(pkcs7.OIDDigestAlgorithmSHA1) {
		t.Fatalf("PK7Digest() returned unexpected digest %q", digest)
	}

	opts.PKCS7Digest = ""
	_, err = opts.PK7Digest()
	if err == nil {
		t.Fatalf("PK7Digest() did not return error")
	}
}

func TestNoID(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	// init a signer, don't care which one, taking this one because p256 is fast
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	// sign input data with bad option
	_, err = s.SignData(input, struct{ Foo string }{Foo: "bar"})
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if err.Error() != "xpi: missing common name" {
		t.Fatalf("expected to fail with missing CN but got error '%v'", err)
	}
}

func TestBadCOSEAlgsErrs(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	// init a signer, don't care which one, taking this one because p256 is fast
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	// sign input data with invalid cose algs option
	_, err = s.SignData(input, Options{
		ID:             "ffffffff-ffff-ffff-ffff-ffffffffffff",
		PKCS7Digest:    "SHA1",
		COSEAlgorithms: []string{"bar"},
	})
	expectedErr := "xpi: cannot use /sign/data for COSE signatures. Use /sign/file instead"
	if err == nil {
		t.Fatal("bad COSE Algs should have errored by didn't")
	} else if err.Error() != expectedErr {
		t.Fatalf("bad COSE Algs should have failed with %q but failed with %q instead", expectedErr, err.Error())
	}

	// sign input data with valid cose algs option
	_, err = s.SignData(input, Options{
		ID:             "ffffffff-ffff-ffff-ffff-ffffffffffff",
		PKCS7Digest:    "SHA1",
		COSEAlgorithms: []string{"ES256"},
	})
	expectedErr = "xpi: cannot use /sign/data for COSE signatures. Use /sign/file instead"
	if err == nil {
		t.Fatal("bad COSE Algs should have errored by didn't")
	} else if err.Error() != expectedErr {
		t.Fatalf("bad COSE Algs should have failed with %q but failed with %q instead", expectedErr, err.Error())
	}
}

func TestBadPKCS7DigestErrs(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	// init a signer, don't care which one, taking this one because p256 is fast
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	// sign input data with invalid pkcs7_digest options
	_, err = s.SignData(input, Options{
		ID:          "ffffffff-ffff-ffff-ffff-ffffffffffff",
		PKCS7Digest: "SHA9000",
	})
	expectedErr := "xpi: can only use SHA1 digests with /sign/data. Use /sign/file instead"
	if err == nil {
		t.Fatal("bad PKCS7 digest should have errored by didn't")
	} else if err.Error() != expectedErr {
		t.Fatalf("bad PKCS7 digest should have failed with %q but failed with %q instead", expectedErr, err.Error())
	}
}

func TestMarshalUnfinishedSignature(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	// init a signer, don't care which one, taking this one because p256 is fast
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	// sign input data with bad option
	sig, err := s.SignData(input, struct{ ID string }{ID: "foo@bar.net"})
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}
	sig.(*Signature).Finished = false
	_, err = sig.Marshal()
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if err.Error() != "xpi: cannot marshal unfinished signature" {
		t.Fatalf("expected to fail marshalling unfinished signature but got error '%v'", err)
	}
}

func TestMarshalEmptySignature(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	// init a signer, don't care which one, taking this one because p256 is fast
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	// sign input data with bad option
	sig, err := s.SignData(input, struct{ ID string }{ID: "foo@bar.net"})
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}
	sig.(*Signature).Data = []byte("")
	_, err = sig.Marshal()
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if err.Error() != "xpi: cannot marshal empty signature data" {
		t.Fatalf("expected to fail marshalling empty signature but got error '%v'", err)
	}
}

func TestUnmarshalBadSignatureBase64(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal(`{{{{{`, []byte("foo"))
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if !strings.HasPrefix(err.Error(), "xpi.Unmarshal: failed to decode base64 signature") {
		t.Fatalf("expected to fail unmarshalling invalid base64 but got error '%v'", err)
	}
}

func TestUnmarshalBadSignaturePKCS7(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal(`Y2FyaWJvdW1hdXJpY2UK`, []byte("foo"))
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if !strings.HasPrefix(err.Error(), "xpi.Unmarshal: failed to parse pkcs7 signature") {
		t.Fatalf("expected to fail parsing bad pkcs7 but got error '%v'", err)
	}
}

func TestVerifyUnfinishedSignature(t *testing.T) {
	t.Parallel()

	input := []byte("foobarbaz1234abcd")
	// init a signer, don't care which one, taking this one because p256 is fast
	s, err := New(validSignerConfigs[3], nil)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}
	// sign input data with bad option
	sig, err := s.SignData(input, struct{ ID string }{ID: "foo@bar.net"})
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}
	sig.(*Signature).Finished = false
	err = sig.(*Signature).VerifyWithChain(nil)
	if err == nil {
		t.Fatal("should have errored by didn't")
	} else if err.Error() != "xpi.VerifyWithChain: cannot verify unfinished signature" {
		t.Fatalf("expected to fail verify unfinished signature but got error '%v'", err)
	}
}

func TestSignFileWithCOSESignatures(t *testing.T) {
	t.Parallel()

	input := unsignedBootstrap
	// initialize a signer
	testcase := validSignerConfigs[0]
	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}

	// sign input data
	signOptions := Options{
		ID:             "test@example.net",
		COSEAlgorithms: []string{"ES256", "PS256"},
		PKCS7Digest:    "SHA1",
	}
	signedXPI, err := s.SignFile(input, signOptions)
	if err != nil {
		t.Fatalf("failed to sign file: %v", err)
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(testcase.Certificate))
	if !ok {
		t.Fatalf("failed to add root cert to pool")
	}

	err = VerifySignedFile(signedXPI, roots, signOptions, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to verify signed file: %v", err)
	}

	// test failure for unknown COSE Alg
	signOptions = Options{
		ID:             "test@example.net",
		COSEAlgorithms: []string{"ROT13"},
	}
	_, err = s.SignFile(input, signOptions)
	if err == nil {
		t.Fatalf("failed to sign file did not fail for unknown alg: %v", err)
	}
}

var validSignerConfigs = []signer.Configuration{
	signer.Configuration{
		ID:   "rsa addon",
		Type: Type,
		Mode: ModeAddOn,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
bGxpem9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9w
bWVudDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9m
b3hzZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMTIzNDQwNFoX
DTI3MDMxOTIzNDQwNFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQG
A1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlv
bjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rl
di5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3Rj
YUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMdX
5soUuvWnkVHRHN5BKByrgpuU3QioE8SNT7BwRFeqbOySdvu5ecQAdNUoRbRyFmNB
ety2rQM9qw6y8eSe9fufIgrv1sg/xj7vweLmuC8Ob+zo5/iwRQw4JUdXnDjwX3W0
auh0QRYfxWGK3hVrP9j1zIJk/yRBornCvXTtn8C/hVSE/PWc6CuV8vTcpyj+TPni
Lvulq17NdlX5qgUdn1yougJxnznkwnoIaBYLdAyZJJIUEomiEIxfabjnh8rfSMIw
AqmslrC8F73yo4JrCqJPt1ipggfpO3ZAjlEoTMcTUgyqR8B35GyuywWR0XrkJV7N
A7BM1qNjLb2to0XQSrGyWA7uPw88LuVk2aUPDE5uNK5Kv//+SGChUn2fDZTsjj3J
KY7f39JVwh/nk8ZkApplne8fKPoknW7er2R+rejyBx1+fJjLegKQsATpgKz4LRf4
ct34oWSV6QXrZ/KKW+frWoHncy8C+UnCC3cDBKs272yqOvBoGMQTrF5oMn8i/Rap
gBbBdwysdJXb+buf/+ZS0PUt7avKFIlXqCNZjG3xotBsTuCL5zAoVKoXJW1FwrcZ
pveQuishKWNf9Id+0HaBdDp/vlbrTwXD1zsxfYvYw8wI7NkNO3TQBni5iyG4B1wh
oR+Z5AebWuJqVnsJyjPakNiuhKNsO/xTa4TF/ymfAgMBAAGjggHcMIIB2DAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDAzAdBgNVHQ4EFgQU2LRpqTdeQ1QlBWNA6fYAqHdpSaUwgekGA1UdIwSB4TCB
3oAU2LRpqTdeQ1QlBWNA6fYAqHdpSaWhgcKkgb8wgbwxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxs
aXpvbSBDb3Jwb3JhdGlvbjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1l
bnQxGDAWBgNVBAMTD2Rldi5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94
c2VjK2RldmFtb3Jvb3RjYUBtb3ppbGxhLmNvbYIBATBCBglghkgBhvhCAQQENRYz
aHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jcmwu
cGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6Ly9jb250ZW50
LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJKoZIhvcNAQEL
BQADggIBALqVt54WTkxD5U5fHPRUSZA9rFigoIcrHNrq+gTDd057cBDUWNc0cEHV
qaP0zgzqD2bIhV/WWlfMDY3VnB8L2+Vjvu2CEt8/9Kh5x9IgBmZt5VUMuEdmQOyH
vA7lz3UI+jmUGcojtLsi+sf4kxDZh3QB3T/wGiHg+K7vXnY7GWEy1Cjfwk/dvbT2
ODTb5B3SPGsh75VmfzFGgerzsS71LN4FYBRUklLe8ozqKF8r/jGE2vfDR1Cy09pN
oR9ti+zaBiEtMlWJjxYrv7HvuoDR9xLmPxyV6gQbo6NnbudkpNdg5LhbY3WV1IgL
TnwJ7aHXgzOZ3w/VsSctg4beZZgYnr81vLKyefWJH1VzCe5XTgwXC1R/afGiVJ0P
hA1+T4My9oTaQBsiNYA2keXKJbTKerMTupoLgV/lJjxfF5BfQiy9NL18/bzxqf+J
7w4P/4oHt3QCdISAIhlG4ttXfRR8oz6obAb6QYdCf3x9b2/3UXKd3UJ+gwchPjj6
InnLK8ig9scn4opVNkBkjlMRsq1yd017eQzLSirpKj3br69qyLoyb/nPNJi7bL1K
bf6m5mF5GmKR+Glvq74O8rLQZ3a75v6H+NwOqAlZnWSJmC84R2HHsHPBw+2pExJT
E5bRcttRlhEdN4NJ2vWJnOH0DENHy6TEwACINJVx6ftucfPfvOxI
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN PRIVATE KEY-----
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
PIDNiTxNecePOmrD+1ivAEXcoL+e1w==
-----END PRIVATE KEY-----`,
	},
	{
		ID:   "rsa system addon",
		Type: Type,
		Mode: ModeSystemAddOn,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
bGxpem9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9w
bWVudDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9m
b3hzZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMTIzNDQwNFoX
DTI3MDMxOTIzNDQwNFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQG
A1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlv
bjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rl
di5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3Rj
YUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMdX
5soUuvWnkVHRHN5BKByrgpuU3QioE8SNT7BwRFeqbOySdvu5ecQAdNUoRbRyFmNB
ety2rQM9qw6y8eSe9fufIgrv1sg/xj7vweLmuC8Ob+zo5/iwRQw4JUdXnDjwX3W0
auh0QRYfxWGK3hVrP9j1zIJk/yRBornCvXTtn8C/hVSE/PWc6CuV8vTcpyj+TPni
Lvulq17NdlX5qgUdn1yougJxnznkwnoIaBYLdAyZJJIUEomiEIxfabjnh8rfSMIw
AqmslrC8F73yo4JrCqJPt1ipggfpO3ZAjlEoTMcTUgyqR8B35GyuywWR0XrkJV7N
A7BM1qNjLb2to0XQSrGyWA7uPw88LuVk2aUPDE5uNK5Kv//+SGChUn2fDZTsjj3J
KY7f39JVwh/nk8ZkApplne8fKPoknW7er2R+rejyBx1+fJjLegKQsATpgKz4LRf4
ct34oWSV6QXrZ/KKW+frWoHncy8C+UnCC3cDBKs272yqOvBoGMQTrF5oMn8i/Rap
gBbBdwysdJXb+buf/+ZS0PUt7avKFIlXqCNZjG3xotBsTuCL5zAoVKoXJW1FwrcZ
pveQuishKWNf9Id+0HaBdDp/vlbrTwXD1zsxfYvYw8wI7NkNO3TQBni5iyG4B1wh
oR+Z5AebWuJqVnsJyjPakNiuhKNsO/xTa4TF/ymfAgMBAAGjggHcMIIB2DAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDAzAdBgNVHQ4EFgQU2LRpqTdeQ1QlBWNA6fYAqHdpSaUwgekGA1UdIwSB4TCB
3oAU2LRpqTdeQ1QlBWNA6fYAqHdpSaWhgcKkgb8wgbwxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxs
aXpvbSBDb3Jwb3JhdGlvbjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1l
bnQxGDAWBgNVBAMTD2Rldi5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94
c2VjK2RldmFtb3Jvb3RjYUBtb3ppbGxhLmNvbYIBATBCBglghkgBhvhCAQQENRYz
aHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jcmwu
cGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6Ly9jb250ZW50
LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJKoZIhvcNAQEL
BQADggIBALqVt54WTkxD5U5fHPRUSZA9rFigoIcrHNrq+gTDd057cBDUWNc0cEHV
qaP0zgzqD2bIhV/WWlfMDY3VnB8L2+Vjvu2CEt8/9Kh5x9IgBmZt5VUMuEdmQOyH
vA7lz3UI+jmUGcojtLsi+sf4kxDZh3QB3T/wGiHg+K7vXnY7GWEy1Cjfwk/dvbT2
ODTb5B3SPGsh75VmfzFGgerzsS71LN4FYBRUklLe8ozqKF8r/jGE2vfDR1Cy09pN
oR9ti+zaBiEtMlWJjxYrv7HvuoDR9xLmPxyV6gQbo6NnbudkpNdg5LhbY3WV1IgL
TnwJ7aHXgzOZ3w/VsSctg4beZZgYnr81vLKyefWJH1VzCe5XTgwXC1R/afGiVJ0P
hA1+T4My9oTaQBsiNYA2keXKJbTKerMTupoLgV/lJjxfF5BfQiy9NL18/bzxqf+J
7w4P/4oHt3QCdISAIhlG4ttXfRR8oz6obAb6QYdCf3x9b2/3UXKd3UJ+gwchPjj6
InnLK8ig9scn4opVNkBkjlMRsq1yd017eQzLSirpKj3br69qyLoyb/nPNJi7bL1K
bf6m5mF5GmKR+Glvq74O8rLQZ3a75v6H+NwOqAlZnWSJmC84R2HHsHPBw+2pExJT
E5bRcttRlhEdN4NJ2vWJnOH0DENHy6TEwACINJVx6ftucfPfvOxI
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN PRIVATE KEY-----
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
PIDNiTxNecePOmrD+1ivAEXcoL+e1w==
-----END PRIVATE KEY-----`,
	},
	{
		Type: Type,
		ID:   "rsa extension",
		Mode: ModeExtension,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
bGxpem9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9w
bWVudDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9m
b3hzZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMTIzNDQwNFoX
DTI3MDMxOTIzNDQwNFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQG
A1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlv
bjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rl
di5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3Rj
YUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMdX
5soUuvWnkVHRHN5BKByrgpuU3QioE8SNT7BwRFeqbOySdvu5ecQAdNUoRbRyFmNB
ety2rQM9qw6y8eSe9fufIgrv1sg/xj7vweLmuC8Ob+zo5/iwRQw4JUdXnDjwX3W0
auh0QRYfxWGK3hVrP9j1zIJk/yRBornCvXTtn8C/hVSE/PWc6CuV8vTcpyj+TPni
Lvulq17NdlX5qgUdn1yougJxnznkwnoIaBYLdAyZJJIUEomiEIxfabjnh8rfSMIw
AqmslrC8F73yo4JrCqJPt1ipggfpO3ZAjlEoTMcTUgyqR8B35GyuywWR0XrkJV7N
A7BM1qNjLb2to0XQSrGyWA7uPw88LuVk2aUPDE5uNK5Kv//+SGChUn2fDZTsjj3J
KY7f39JVwh/nk8ZkApplne8fKPoknW7er2R+rejyBx1+fJjLegKQsATpgKz4LRf4
ct34oWSV6QXrZ/KKW+frWoHncy8C+UnCC3cDBKs272yqOvBoGMQTrF5oMn8i/Rap
gBbBdwysdJXb+buf/+ZS0PUt7avKFIlXqCNZjG3xotBsTuCL5zAoVKoXJW1FwrcZ
pveQuishKWNf9Id+0HaBdDp/vlbrTwXD1zsxfYvYw8wI7NkNO3TQBni5iyG4B1wh
oR+Z5AebWuJqVnsJyjPakNiuhKNsO/xTa4TF/ymfAgMBAAGjggHcMIIB2DAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDAzAdBgNVHQ4EFgQU2LRpqTdeQ1QlBWNA6fYAqHdpSaUwgekGA1UdIwSB4TCB
3oAU2LRpqTdeQ1QlBWNA6fYAqHdpSaWhgcKkgb8wgbwxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxs
aXpvbSBDb3Jwb3JhdGlvbjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1l
bnQxGDAWBgNVBAMTD2Rldi5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94
c2VjK2RldmFtb3Jvb3RjYUBtb3ppbGxhLmNvbYIBATBCBglghkgBhvhCAQQENRYz
aHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jcmwu
cGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6Ly9jb250ZW50
LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJKoZIhvcNAQEL
BQADggIBALqVt54WTkxD5U5fHPRUSZA9rFigoIcrHNrq+gTDd057cBDUWNc0cEHV
qaP0zgzqD2bIhV/WWlfMDY3VnB8L2+Vjvu2CEt8/9Kh5x9IgBmZt5VUMuEdmQOyH
vA7lz3UI+jmUGcojtLsi+sf4kxDZh3QB3T/wGiHg+K7vXnY7GWEy1Cjfwk/dvbT2
ODTb5B3SPGsh75VmfzFGgerzsS71LN4FYBRUklLe8ozqKF8r/jGE2vfDR1Cy09pN
oR9ti+zaBiEtMlWJjxYrv7HvuoDR9xLmPxyV6gQbo6NnbudkpNdg5LhbY3WV1IgL
TnwJ7aHXgzOZ3w/VsSctg4beZZgYnr81vLKyefWJH1VzCe5XTgwXC1R/afGiVJ0P
hA1+T4My9oTaQBsiNYA2keXKJbTKerMTupoLgV/lJjxfF5BfQiy9NL18/bzxqf+J
7w4P/4oHt3QCdISAIhlG4ttXfRR8oz6obAb6QYdCf3x9b2/3UXKd3UJ+gwchPjj6
InnLK8ig9scn4opVNkBkjlMRsq1yd017eQzLSirpKj3br69qyLoyb/nPNJi7bL1K
bf6m5mF5GmKR+Glvq74O8rLQZ3a75v6H+NwOqAlZnWSJmC84R2HHsHPBw+2pExJT
E5bRcttRlhEdN4NJ2vWJnOH0DENHy6TEwACINJVx6ftucfPfvOxI
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN PRIVATE KEY-----
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
PIDNiTxNecePOmrD+1ivAEXcoL+e1w==
-----END PRIVATE KEY-----`,
	},
	{
		Type: Type,
		ID:   "ecdsa addon",
		Mode: ModeAddOn,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEaDCCA+6gAwIBAgIBATAKBggqhkjOPQQDAjCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMjExNDg0MFoXDTI3
MDMyMDExNDg0MFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlvbjEg
MB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rldi5h
bW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3RjYUBt
b3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD0rcBU0tirO38TeyZXU
4jz+2v2ngib0I7ABJ4dQg5ZEfC7nW1HvgbKowwjxqPJnpB+W+RUcnsdspj91uwv9
RW22eGPLY8Oot7cgULitIXpBJ1ChHTCMWkzQ/C3jBYAoe6OCAcAwggG8MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMDMB0GA1UdDgQWBBQoV8bn7ADMjKLF9XAIwDeEdqn8bDCB6QYDVR0jBIHhMIHe
gBQoV8bn7ADMjKLF9XAIwDeEdqn8bKGBwqSBvzCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tggEBMDQGCWCGSAGG+EIBBAQnFiVo
dHRwczovL2Ftby5kZXYubW96YXdzLm5ldC9jYS9jcmwucGVtMEAGCCsGAQUFBwEB
BDQwMjAwBggrBgEFBQcwAoYkaHR0cHM6Ly9hbW8uZGV2Lm1vemF3cy5uZXQvY2Ev
Y2EucGVtMAoGCCqGSM49BAMCA2gAMGUCMH/W3TjLf0giza8y83S0f4i21b1hSxEv
DZ0QKXuha63GeB4qNOcqqE0Zh7ttWhZ2lQIxANlADi6ZTdDtByJL/QKbk9hKGJCE
wMlTLnlLg0nhVXAEq2SRaF7Tx/v4Ny9kuR7p5A==
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRB9WEMGnGieJ+Vpy0s4Lg/nfONiJTNynL0z/yC4/arw1TX5MhS9/2
Hx2rI3n9NUmgBwYFK4EEACKhZANiAAQ9K3AVNLYqzt/E3smV1OI8/tr9p4Im9COw
ASeHUIOWRHwu51tR74GyqMMI8ajyZ6QflvkVHJ7HbKY/dbsL/UVttnhjy2PDqLe3
IFC4rSF6QSdQoR0wjFpM0Pwt4wWAKHs=
-----END EC PRIVATE KEY-----`,
	},
	{
		Type: Type,
		ID:   "ecdsa addon with rec",
		Mode: ModeAddOnWithRecommendation,
		RecommendationConfig: signer.RecommendationConfig{
			AllowedStates: map[string]bool{
				"standard":    true,
				"recommended": true,
			},
			FilePath:              "test-recommendations.json",
			ValidityRelativeStart: time.Minute,
			ValidityDuration:      5 * 365 * time.Hour,
		},
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEaDCCA+6gAwIBAgIBATAKBggqhkjOPQQDAjCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMjExNDg0MFoXDTI3
MDMyMDExNDg0MFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlvbjEg
MB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rldi5h
bW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3RjYUBt
b3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD0rcBU0tirO38TeyZXU
4jz+2v2ngib0I7ABJ4dQg5ZEfC7nW1HvgbKowwjxqPJnpB+W+RUcnsdspj91uwv9
RW22eGPLY8Oot7cgULitIXpBJ1ChHTCMWkzQ/C3jBYAoe6OCAcAwggG8MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMDMB0GA1UdDgQWBBQoV8bn7ADMjKLF9XAIwDeEdqn8bDCB6QYDVR0jBIHhMIHe
gBQoV8bn7ADMjKLF9XAIwDeEdqn8bKGBwqSBvzCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tggEBMDQGCWCGSAGG+EIBBAQnFiVo
dHRwczovL2Ftby5kZXYubW96YXdzLm5ldC9jYS9jcmwucGVtMEAGCCsGAQUFBwEB
BDQwMjAwBggrBgEFBQcwAoYkaHR0cHM6Ly9hbW8uZGV2Lm1vemF3cy5uZXQvY2Ev
Y2EucGVtMAoGCCqGSM49BAMCA2gAMGUCMH/W3TjLf0giza8y83S0f4i21b1hSxEv
DZ0QKXuha63GeB4qNOcqqE0Zh7ttWhZ2lQIxANlADi6ZTdDtByJL/QKbk9hKGJCE
wMlTLnlLg0nhVXAEq2SRaF7Tx/v4Ny9kuR7p5A==
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRB9WEMGnGieJ+Vpy0s4Lg/nfONiJTNynL0z/yC4/arw1TX5MhS9/2
Hx2rI3n9NUmgBwYFK4EEACKhZANiAAQ9K3AVNLYqzt/E3smV1OI8/tr9p4Im9COw
ASeHUIOWRHwu51tR74GyqMMI8ajyZ6QflvkVHJ7HbKY/dbsL/UVttnhjy2PDqLe3
IFC4rSF6QSdQoR0wjFpM0Pwt4wWAKHs=
-----END EC PRIVATE KEY-----`,
	},
	{
		Type: Type,
		ID:   "ecdsa system addon",
		Mode: ModeSystemAddOn,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEaDCCA+6gAwIBAgIBATAKBggqhkjOPQQDAjCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMjExNDg0MFoXDTI3
MDMyMDExNDg0MFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlvbjEg
MB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rldi5h
bW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3RjYUBt
b3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD0rcBU0tirO38TeyZXU
4jz+2v2ngib0I7ABJ4dQg5ZEfC7nW1HvgbKowwjxqPJnpB+W+RUcnsdspj91uwv9
RW22eGPLY8Oot7cgULitIXpBJ1ChHTCMWkzQ/C3jBYAoe6OCAcAwggG8MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMDMB0GA1UdDgQWBBQoV8bn7ADMjKLF9XAIwDeEdqn8bDCB6QYDVR0jBIHhMIHe
gBQoV8bn7ADMjKLF9XAIwDeEdqn8bKGBwqSBvzCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tggEBMDQGCWCGSAGG+EIBBAQnFiVo
dHRwczovL2Ftby5kZXYubW96YXdzLm5ldC9jYS9jcmwucGVtMEAGCCsGAQUFBwEB
BDQwMjAwBggrBgEFBQcwAoYkaHR0cHM6Ly9hbW8uZGV2Lm1vemF3cy5uZXQvY2Ev
Y2EucGVtMAoGCCqGSM49BAMCA2gAMGUCMH/W3TjLf0giza8y83S0f4i21b1hSxEv
DZ0QKXuha63GeB4qNOcqqE0Zh7ttWhZ2lQIxANlADi6ZTdDtByJL/QKbk9hKGJCE
wMlTLnlLg0nhVXAEq2SRaF7Tx/v4Ny9kuR7p5A==
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRB9WEMGnGieJ+Vpy0s4Lg/nfONiJTNynL0z/yC4/arw1TX5MhS9/2
Hx2rI3n9NUmgBwYFK4EEACKhZANiAAQ9K3AVNLYqzt/E3smV1OI8/tr9p4Im9COw
ASeHUIOWRHwu51tR74GyqMMI8ajyZ6QflvkVHJ7HbKY/dbsL/UVttnhjy2PDqLe3
IFC4rSF6QSdQoR0wjFpM0Pwt4wWAKHs=
-----END EC PRIVATE KEY-----`,
	},
	{
		Type: Type,
		ID:   "ecdsa extension",
		Mode: ModeExtension,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEaDCCA+6gAwIBAgIBATAKBggqhkjOPQQDAjCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMjExNDg0MFoXDTI3
MDMyMDExNDg0MFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlvbjEg
MB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rldi5h
bW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3RjYUBt
b3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD0rcBU0tirO38TeyZXU
4jz+2v2ngib0I7ABJ4dQg5ZEfC7nW1HvgbKowwjxqPJnpB+W+RUcnsdspj91uwv9
RW22eGPLY8Oot7cgULitIXpBJ1ChHTCMWkzQ/C3jBYAoe6OCAcAwggG8MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMDMB0GA1UdDgQWBBQoV8bn7ADMjKLF9XAIwDeEdqn8bDCB6QYDVR0jBIHhMIHe
gBQoV8bn7ADMjKLF9XAIwDeEdqn8bKGBwqSBvzCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tggEBMDQGCWCGSAGG+EIBBAQnFiVo
dHRwczovL2Ftby5kZXYubW96YXdzLm5ldC9jYS9jcmwucGVtMEAGCCsGAQUFBwEB
BDQwMjAwBggrBgEFBQcwAoYkaHR0cHM6Ly9hbW8uZGV2Lm1vemF3cy5uZXQvY2Ev
Y2EucGVtMAoGCCqGSM49BAMCA2gAMGUCMH/W3TjLf0giza8y83S0f4i21b1hSxEv
DZ0QKXuha63GeB4qNOcqqE0Zh7ttWhZ2lQIxANlADi6ZTdDtByJL/QKbk9hKGJCE
wMlTLnlLg0nhVXAEq2SRaF7Tx/v4Ny9kuR7p5A==
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRB9WEMGnGieJ+Vpy0s4Lg/nfONiJTNynL0z/yC4/arw1TX5MhS9/2
Hx2rI3n9NUmgBwYFK4EEACKhZANiAAQ9K3AVNLYqzt/E3smV1OI8/tr9p4Im9COw
ASeHUIOWRHwu51tR74GyqMMI8ajyZ6QflvkVHJ7HbKY/dbsL/UVttnhjy2PDqLe3
IFC4rSF6QSdQoR0wjFpM0Pwt4wWAKHs=
-----END EC PRIVATE KEY-----`,
	},
	{
		Type: Type,
		ID:   "ecdsa hotfix",
		Mode: ModeHotFix,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEaDCCA+6gAwIBAgIBATAKBggqhkjOPQQDAjCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMjExNDg0MFoXDTI3
MDMyMDExNDg0MFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlvbjEg
MB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rldi5h
bW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3RjYUBt
b3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD0rcBU0tirO38TeyZXU
4jz+2v2ngib0I7ABJ4dQg5ZEfC7nW1HvgbKowwjxqPJnpB+W+RUcnsdspj91uwv9
RW22eGPLY8Oot7cgULitIXpBJ1ChHTCMWkzQ/C3jBYAoe6OCAcAwggG8MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMDMB0GA1UdDgQWBBQoV8bn7ADMjKLF9XAIwDeEdqn8bDCB6QYDVR0jBIHhMIHe
gBQoV8bn7ADMjKLF9XAIwDeEdqn8bKGBwqSBvzCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tggEBMDQGCWCGSAGG+EIBBAQnFiVo
dHRwczovL2Ftby5kZXYubW96YXdzLm5ldC9jYS9jcmwucGVtMEAGCCsGAQUFBwEB
BDQwMjAwBggrBgEFBQcwAoYkaHR0cHM6Ly9hbW8uZGV2Lm1vemF3cy5uZXQvY2Ev
Y2EucGVtMAoGCCqGSM49BAMCA2gAMGUCMH/W3TjLf0giza8y83S0f4i21b1hSxEv
DZ0QKXuha63GeB4qNOcqqE0Zh7ttWhZ2lQIxANlADi6ZTdDtByJL/QKbk9hKGJCE
wMlTLnlLg0nhVXAEq2SRaF7Tx/v4Ny9kuR7p5A==
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCRB9WEMGnGieJ+Vpy0s4Lg/nfONiJTNynL0z/yC4/arw1TX5MhS9/2
Hx2rI3n9NUmgBwYFK4EEACKhZANiAAQ9K3AVNLYqzt/E3smV1OI8/tr9p4Im9COw
ASeHUIOWRHwu51tR74GyqMMI8ajyZ6QflvkVHJ7HbKY/dbsL/UVttnhjy2PDqLe3
IFC4rSF6QSdQoR0wjFpM0Pwt4wWAKHs=
-----END EC PRIVATE KEY-----`,
	},
	// valid NotBefore 2019-06-14 18:40:21 UTC and NotAfter 2021-01-14 18:40:21 UTC
	signer.Configuration{
		ID:   "ecdsa addon expired intermediate",
		Type: Type,
		Mode: ModeAddOn,
		Certificate: `
-----BEGIN CERTIFICATE-----
MIICaTCCAfCgAwIBAgIIFpJZf/0ls9swCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNjI2NDYwODIxMB4XDTE5MDYxNDE4
NDAyMVoXDTIxMDExNDE4NDAyMVowYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
VQQDExFjc2ludGVyMTYyNjQ2MDgyMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABDw3
+rbWEmoolOex/o83sErQIFzfiUk3rHH1jsjc6Y3JYApiS4kEi/9W6GB170eLevQX
tZlSzR/tQHZ9ckh5TdHDGCqzSW1bQS/Ve6GVBlIMLlL8Odvaiqs8bLtjXoLhb6N4
MHYwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0OBBYEFKEbMQtSCbmKeI0S0AFyN+MUq7WRMB8GA1UdIwQY
MBaAFIMp+z7aIARHJQK6dnqO46cgLFvqMAoGCCqGSM49BAMDA2cAMGQCMF8GvKhZ
9w7E9UEAo23EeImZGDXWP1BPQzLcKJEHNIxd/bBwvQcj4BAsE3xgWEbjCQIwGqed
v+d1uifbc8/SgGVWazxyofFhpRik7UJk5Hz4hebIwm08HT8FYFHvH+d2xIXw
-----END CERTIFICATE-----
`,
		PrivateKey: `
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAYedcRd6GfNMPT0bXcidNMReNy/v+cR9236bkm7sEEgJ2pD9WHK2i6
GJb5Zv3/scygBwYFK4EEACKhZANiAAQ8N/q21hJqKJTnsf6PN7BK0CBc34lJN6xx
9Y7I3OmNyWAKYkuJBIv/Vuhgde9Hi3r0F7WZUs0f7UB2fXJIeU3Rwxgqs0ltW0Ev
1XuhlQZSDC5S/Dnb2oqrPGy7Y16C4W8=
-----END EC PRIVATE KEY-----`,
	},
}

var invalidSignerConfigs = []struct {
	err string
	cfg signer.Configuration
}{
	{err: "xpi: invalid type", cfg: signer.Configuration{Type: ""}},
	{err: "xpi: missing signer ID in signer configuration", cfg: signer.Configuration{Type: Type, ID: ""}},
	{err: "xpi: missing private key in signer configuration", cfg: signer.Configuration{Type: Type, ID: "bob"}},
	{err: "xpi: GetKeys failed to retrieve signer: no suitable key found", cfg: signer.Configuration{Type: Type, ID: "bob", PrivateKey: "Ym9iCg=="}},
	{err: "xpi: failed to parse certificate PEM", cfg: signer.Configuration{
		Type:        Type,
		ID:          "abcd",
		Certificate: "foo",
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
	{err: "xpi: signer certificate must have CA constraint set to true", cfg: signer.Configuration{
		Type: Type,
		ID:   "abcd",
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIEPDCCAySgAwIBAgISAxw8x5gKJ8VwTpiqA8lVKdGGMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzA2MDEwOTUyMDBaFw0x
NzA4MzAwOTUyMDBaMBIxEDAOBgNVBAMTB3VsZnIuaW8wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAAQTKrZyhtj9EIo5t1DTEGlBZh7Q5acBxXP/SJZfcg2jqZuVKy1k
quIpB7U/2cwQdbXRoePG9rN5gaJlGF+1aVkVo4ICHTCCAhkwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAA
MB0GA1UdDgQWBBSgPuc3AB9rq0tK+t48oz56nk66FDAfBgNVHSMEGDAWgBSoSmpj
BH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0
dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0
dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMCgGA1UdEQQhMB+CFGph
ZmZhLmxpbnV4d2FsbC5pbmZvggd1bGZyLmlvMIH+BgNVHSAEgfYwgfMwCAYGZ4EM
AQIBMIHmBgsrBgEEAYLfEwEBATCB1jAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5s
ZXRzZW5jcnlwdC5vcmcwgasGCCsGAQUFBwICMIGeDIGbVGhpcyBDZXJ0aWZpY2F0
ZSBtYXkgb25seSBiZSByZWxpZWQgdXBvbiBieSBSZWx5aW5nIFBhcnRpZXMgYW5k
IG9ubHkgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBDZXJ0aWZpY2F0ZSBQb2xpY3kg
Zm91bmQgYXQgaHR0cHM6Ly9sZXRzZW5jcnlwdC5vcmcvcmVwb3NpdG9yeS8wDQYJ
KoZIhvcNAQELBQADggEBAF0DPnKAibulmxjurWV8/plAEmcyK1uHp/GKvafaOEdI
OgnYItG8aWXhjIKioNwUZShkTRpqXq+lXm1gexUanHGvAPaPyUNKqI1SizBvIWrk
j33X8KJMrfealADjl2gMtm12BfE3CfDN1o97mLBE4NgXV9O6nhuWiyICjk0Bb9uP
zi8/SNl5RuDVAjGORJPEJpzAT+RlSSeVybQ6YhV4o9tJhkXTu8vDOOE/JdxU/9IE
nqZfqrhFes4MpAjqvnpdqBTWCxCctgMfi8Va+2V6f5ftIXP/7Hz/OfH5I2EJ1/K2
LFU3osZ2XbLIR6wt+zVFQ5QhMrOUsSEfbbPvVlHHsNo=
-----END CERTIFICATE-----`,
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
	{err: "xpi: signer certificate is missing certificate signing key usage", cfg: signer.Configuration{
		Type: Type,
		ID:   "abcd",
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJALIibhYzEpg4MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwNjIwMTM0MTEwWhcNNDQxMTA1MTM0MTEwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANlh
v6lCpK8vadOxM1/Mdlxki/Aqxtt8cditzwuj+YhMS8OxBVL+YzUqxz35ecfkioyD
u1LL95YjRrNG94rnWpMCAwEAAaNQME4wHQYDVR0OBBYEFKpvay/D28LrITvofh8Z
zfBUTpCUMB8GA1UdIwQYMBaAFKpvay/D28LrITvofh8ZzfBUTpCUMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADQQDTUlPHTR2X2Kq/18E7Ms5i+94/cDQU51m8
YsfMwvTeMTl21zQb6cfvwtZNiHkeXxAtLLcF5/eO3M3s0zSy5y40
-----END CERTIFICATE-----`,
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
	{err: `xpi: unknown signer mode "InvalidMode", must be 'add-on', 'extension', 'system add-on' or 'hotfix'`, cfg: signer.Configuration{
		ID:   "rsa addon",
		Type: Type,
		Mode: "InvalidMode",
		Certificate: `
-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
bGxpem9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9w
bWVudDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9m
b3hzZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMTIzNDQwNFoX
DTI3MDMxOTIzNDQwNFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQG
A1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlv
bjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rl
di5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3Rj
YUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMdX
5soUuvWnkVHRHN5BKByrgpuU3QioE8SNT7BwRFeqbOySdvu5ecQAdNUoRbRyFmNB
ety2rQM9qw6y8eSe9fufIgrv1sg/xj7vweLmuC8Ob+zo5/iwRQw4JUdXnDjwX3W0
auh0QRYfxWGK3hVrP9j1zIJk/yRBornCvXTtn8C/hVSE/PWc6CuV8vTcpyj+TPni
Lvulq17NdlX5qgUdn1yougJxnznkwnoIaBYLdAyZJJIUEomiEIxfabjnh8rfSMIw
AqmslrC8F73yo4JrCqJPt1ipggfpO3ZAjlEoTMcTUgyqR8B35GyuywWR0XrkJV7N
A7BM1qNjLb2to0XQSrGyWA7uPw88LuVk2aUPDE5uNK5Kv//+SGChUn2fDZTsjj3J
KY7f39JVwh/nk8ZkApplne8fKPoknW7er2R+rejyBx1+fJjLegKQsATpgKz4LRf4
ct34oWSV6QXrZ/KKW+frWoHncy8C+UnCC3cDBKs272yqOvBoGMQTrF5oMn8i/Rap
gBbBdwysdJXb+buf/+ZS0PUt7avKFIlXqCNZjG3xotBsTuCL5zAoVKoXJW1FwrcZ
pveQuishKWNf9Id+0HaBdDp/vlbrTwXD1zsxfYvYw8wI7NkNO3TQBni5iyG4B1wh
oR+Z5AebWuJqVnsJyjPakNiuhKNsO/xTa4TF/ymfAgMBAAGjggHcMIIB2DAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDAzAdBgNVHQ4EFgQU2LRpqTdeQ1QlBWNA6fYAqHdpSaUwgekGA1UdIwSB4TCB
3oAU2LRpqTdeQ1QlBWNA6fYAqHdpSaWhgcKkgb8wgbwxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxs
aXpvbSBDb3Jwb3JhdGlvbjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1l
bnQxGDAWBgNVBAMTD2Rldi5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94
c2VjK2RldmFtb3Jvb3RjYUBtb3ppbGxhLmNvbYIBATBCBglghkgBhvhCAQQENRYz
aHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jcmwu
cGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6Ly9jb250ZW50
LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJKoZIhvcNAQEL
BQADggIBALqVt54WTkxD5U5fHPRUSZA9rFigoIcrHNrq+gTDd057cBDUWNc0cEHV
qaP0zgzqD2bIhV/WWlfMDY3VnB8L2+Vjvu2CEt8/9Kh5x9IgBmZt5VUMuEdmQOyH
vA7lz3UI+jmUGcojtLsi+sf4kxDZh3QB3T/wGiHg+K7vXnY7GWEy1Cjfwk/dvbT2
ODTb5B3SPGsh75VmfzFGgerzsS71LN4FYBRUklLe8ozqKF8r/jGE2vfDR1Cy09pN
oR9ti+zaBiEtMlWJjxYrv7HvuoDR9xLmPxyV6gQbo6NnbudkpNdg5LhbY3WV1IgL
TnwJ7aHXgzOZ3w/VsSctg4beZZgYnr81vLKyefWJH1VzCe5XTgwXC1R/afGiVJ0P
hA1+T4My9oTaQBsiNYA2keXKJbTKerMTupoLgV/lJjxfF5BfQiy9NL18/bzxqf+J
7w4P/4oHt3QCdISAIhlG4ttXfRR8oz6obAb6QYdCf3x9b2/3UXKd3UJ+gwchPjj6
InnLK8ig9scn4opVNkBkjlMRsq1yd017eQzLSirpKj3br69qyLoyb/nPNJi7bL1K
bf6m5mF5GmKR+Glvq74O8rLQZ3a75v6H+NwOqAlZnWSJmC84R2HHsHPBw+2pExJT
E5bRcttRlhEdN4NJ2vWJnOH0DENHy6TEwACINJVx6ftucfPfvOxI
-----END CERTIFICATE-----`,
		PrivateKey: `
-----BEGIN PRIVATE KEY-----
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
PIDNiTxNecePOmrD+1ivAEXcoL+e1w==
-----END PRIVATE KEY-----`,
	}},
	{err: "xpi: issuer RSA key must be at least 2048 bits", cfg: signer.Configuration{
		ID:   "short-rsa-1024-addon",
		Type: Type,
		Mode: ModeAddOn,
		Certificate: `-----BEGIN CERTIFICATE-----
MIIC6jCCAlOgAwIBAgIUNaURazaTKH/ojldD9/JTpoVVLbwwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFp
biBWaWV3MRcwFQYDVQQKDA5Nb3ppbGxhIEFkZG9uczESMBAGA1UECwwJVW5pdCBU
ZXN0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAgFw0yMDAyMDcxNjI1NDNaGA8yMTIw
MDExNDE2MjU0M1owdTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQH
DA1Nb3VudGFpbiBWaWV3MRcwFQYDVQQKDA5Nb3ppbGxhIEFkZG9uczESMBAGA1UE
CwwJVW5pdCBUZXN0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEAqUgnQcFFY5YxOKyrlQyP7Y6XSkivXJigx/njCvbTCi4I
yv1HgkfZHqzJzvh+TCOAJ75ncCbcPvaFQxclBSI0Iwv5XkHpw9XNjuGa3A5gy0ei
nztS/ynM3dpjMEAqk0M2L7BKQKye1iXNtb63dbinxyoJqgAvLmd+B/rlnht352UC
AwEAAaN1MHMwHQYDVR0OBBYEFFc3gHz75RNFAPd5aulDZxr2N+GDMB8GA1UdIwQY
MBaAFFc3gHz75RNFAPd5aulDZxr2N+GDMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0P
BAQDAgIEMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBCwUAA4GBAGn2
PnNj0ekSDPFJXybRL2rX4yw1S9qXiaXVHhZXBMoNaeGrB02rIMrDIvP3jRgVLes+
ncRfDgBhVtJoj31z8GJBMMZbeS6Ar+U0zXchMo+8Igxv1HMBwttW1wvE4q4dI7dx
A82++INZTlAo4t5EqGxJL/Lhw6Zqbs7E0IZwMzh7
-----END CERTIFICATE-----
`,
		PrivateKey: `-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKlIJ0HBRWOWMTis
q5UMj+2Ol0pIr1yYoMf54wr20wouCMr9R4JH2R6syc74fkwjgCe+Z3Am3D72hUMX
JQUiNCML+V5B6cPVzY7hmtwOYMtHop87Uv8pzN3aYzBAKpNDNi+wSkCsntYlzbW+
t3W4p8cqCaoALy5nfgf65Z4bd+dlAgMBAAECgYBmQsYkPMLUJBjb6cNFKO+RTEAs
ibgVscX+x//V0cEvNxvstBCMrSaGF09aDlcNW6zBVY5a+7608msSWlrsvPrM7U6I
SNvBSvi7KwubjoUn+bZevYbc+4ApRln/XwetC1ORa5v73dY2sjkqIB87mxEdiYRc
1rE1omSjYF9cutMyyQJBANq9frbcBQ6ygnUzqDoBKFosVr0YvxZ02os09BfzXc3Z
mdT6sfzKfegPI0zymbYAzOnKxACjZ1ADLVMdd/cwGK8CQQDGHfMtwgl8BOGXnmUM
0dCWOs2sWPzZinHkbVJhqxI18wm2PKqSEjXqVI/FoLpEcs2+9aVn/TGyhs4n8E91
xN4rAkAX83fUffLv0QwH2UgqUcYhWYmF2xfRVao4Y+v2U2eKCrGVaH3kuCdhKYcr
/cRm8V9+mf0sNLgzQqXL3AYuws1xAkBergGBZLHTqyGErBXuwnbE1OVl8EEmVZuI
ZxZvxqm1TqjdhrCdjkZl7nOnJuDdxV++Wvbpc39EqlfrjlTrG2JxAkBnVraQ3ZVH
HrYqtoo1xl/h/sOXXPm9PQ7VYgZCpOzasC9ZAYUO7lHmNK+zwmmudFGY+aPM4c/b
a05oGDnmq7R+
-----END PRIVATE KEY-----
`,
	}},
	{err: "xpi: signer certificate does not have code signing EKU", cfg: signer.Configuration{
		ID:   "rsa-no-eku-addon",
		Type: Type,
		Mode: ModeAddOn,
		Certificate: `-----BEGIN CERTIFICATE-----
MIID2jCCAsKgAwIBAgIUKby8CRXqTG1ZgiRqC7r4elHJZSswDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1Nb3VudGFp
biBWaWV3MRcwFQYDVQQKDA5Nb3ppbGxhIEFkZG9uczESMBAGA1UECwwJVW5pdCBU
ZXN0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAgFw0yMDAyMDcxNjI5MThaGA8yMTIw
MDExNDE2MjkxOFowdTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQH
DA1Nb3VudGFpbiBWaWV3MRcwFQYDVQQKDA5Nb3ppbGxhIEFkZG9uczESMBAGA1UE
CwwJVW5pdCBUZXN0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAL23FrR1y8HK+2QxV1IwFf3ak1n1mP0Ci8E8h2/p
/LvYaWhLQFFIyqKmXGqBVW3kGYAMkHS1O371i7vx+iIKzTAgphplY5Q/2aFgeIE5
s2jsX/6zIjsLDDHJqLN++aUsc/rUSEXhRGgRAIx1SlN+lNEw4Th2HNN9G9kFjBH9
VoB8rfQ6jQF+ZDABXI34vImW7orbl8GVCXN6B4tvu+6EnJPV635uyo/A36cmjXs0
1WbucVfrshh1DU/dMEQ8rw+vlY5HA5EgLLdW1jJr4YkwNHuQ4bTnVonyn07SRzG4
MJXIHyIhrKl6/eNXd17DsdqSppqEdmTUiZcN0sZHTVzimdECAwEAAaNgMF4wHQYD
VR0OBBYEFMzCoqr1NIhTVscT/hEEPbc8BnC0MB8GA1UdIwQYMBaAFMzCoqr1NIhT
VscT/hEEPbc8BnC0MA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgIEMA0GCSqG
SIb3DQEBCwUAA4IBAQBLszijEFYpxpGhtVUn0V67uLGsaFaUeN32SFKlgsvZE6pm
KxvQL7JiqOMkU7Y7N8nE8aJ/13vamP+vYQM004S3uwnPxxsEeRNX2oX91HQRWzrg
1HoEq4Pzyo2S7/uL+kQPBvePR2NsJNVMCNi/uCwobdQue+evVpEVqYaPWkL1kDGW
/TCeZ10d6HhAhrjq/ms9E4DQny9/tH8SiRu/DuTY6NVgztdZJL8K5Gpx2tCb6c7r
e25OWgCSTOikn4bnsxNWmDa0qbopcJKf2se5DGN2BAQ8OigychlpCf3jqa2ZobOM
Qj+W2dEr/Qw1wo222rh/zkI8kVNXYmgJsfeZKFGB
-----END CERTIFICATE-----
`,
		PrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9txa0dcvByvtk
MVdSMBX92pNZ9Zj9AovBPIdv6fy72GloS0BRSMqiplxqgVVt5BmADJB0tTt+9Yu7
8foiCs0wIKYaZWOUP9mhYHiBObNo7F/+syI7CwwxyaizfvmlLHP61EhF4URoEQCM
dUpTfpTRMOE4dhzTfRvZBYwR/VaAfK30Oo0BfmQwAVyN+LyJlu6K25fBlQlzegeL
b7vuhJyT1et+bsqPwN+nJo17NNVm7nFX67IYdQ1P3TBEPK8Pr5WORwORICy3VtYy
a+GJMDR7kOG051aJ8p9O0kcxuDCVyB8iIaypev3jV3dew7HakqaahHZk1ImXDdLG
R01c4pnRAgMBAAECggEAbxZRVjQPrpdT4tQ9hGOhzPZ7B9cW0Tf3a5ws1ixWEAxl
lGtT6wTLmrf9L2QyCNni0KcKwzwH7YyMWO4VAHAAvCix+ozZ5UoJ/kPF7C1ET7Dx
eOudpKMQberePNSiC8Te2MYK19hTPPiPsK9RaViafW+4wV3v/Sqp7scfwLzuNOdK
fqQrAyUVe40nTpsac407RZ9G8SJC8PPfc4muB45YH6C5GpQNkpFPlX1TVZ54gRgC
f/N9EvZz5pcnWg7kjAiPRaEx6S5eZ1OCKICk3V8Xt54L3P9TiIUGwPcC9eOhToGm
KKKhEgpK1pBuNmqHKWxjPv4VEwg0ru2NL3SXQmCC/QKBgQDmj6GXfbV1Ox5yeC6t
RwMAbFt5hYTtsHutUNGHmP8Y31y+mjN8Rz8iQV5NfHiw7IH9WBDidp6diGN1JD4x
/FKFlY+azK1M0qeHcRBbEKMGtkfZorsFn4H25Hhw4nDbjOtSS/FFenPLDcA6bySm
VkDGGCJGex94k37K5/Uc0zhrTwKBgQDSpbxIyyhKlCOfx0Fj53Xs1SYn4M8PFdlH
afs1NoupHb4unFLkuvm108thPmXOMsKeXFCkFLBcA0EKhZypLZz9F2FFAh0Z/Ip5
SG1BHnWz8lRbDtzvJzWQclFTT8088CIkDuhMTvQBw2rKY55XNpDHt6EdRfqUjU6M
SbZj26jg3wKBgEV2pqe+rwn32s+AGAgKqgPZoaG2MXtvPYPVIpuo48p5mTavvK1H
xeSrLx9HThF34B4VB1lDhbxOmDB1z+s9axtmGRL5cYkAuoqa7OOS2psuFe2jEpe6
G+znnsXb40ayaT+tM67MGtDlfrHcRH185R0JrmHvvGaWgY/eXMHnfUsPAoGBAIje
hYuq7YAf51HPL07Ru07qZENvEDsWEDsVwtMdoPt+xu8URcw3LT+W4URLPe0QEGLD
SuaCRuFSf/VtQZCvgZz1jw8+w1f6PqN1iv/P4dzNbUBJVQbTrDsx/GOsq4eX5CcX
xJqohmWK6x2cQusaGlKan0YdDSdu9YWz853IwV9zAoGAIIGzQAX581j6ziBgJx78
ilZoRcK4IdDhPIji2rEhUWiudboAWq6ljtNcva7tFcdK1UmgBSosuApG0enly1UK
3MZJzZyW4HoGmLYI+FellWJhjm4l6oEOcvb7m0ksZUkcuJcIdZVoLWq77kZ87ofN
eT6Q43/gPKpGi5Sq1heGugQ=
-----END PRIVATE KEY-----
`,
	}},
	// rsa-no-eku-addon with the second line of the cert removed
	{err: "xpi: could not parse X.509 certificate:", cfg: signer.Configuration{
		ID:   "rsa-bad-x509",
		Type: Type,
		Mode: ModeAddOn,
		Certificate: `-----BEGIN CERTIFICATE-----
BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEXMBUG
A1UECgwOTW96aWxsYSBBZGRvbnMxEjAQBgNVBAsMCVVuaXQgVGVzdDEUMBIGA1UE
AwwLZXhhbXBsZS5jb20wHhcNMTkwMTI1MTU1NjM5WhcNMjAwMTI1MTU1NjM5WjB1
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZp
ZXcxFzAVBgNVBAoMDk1vemlsbGEgQWRkb25zMRIwEAYDVQQLDAlVbml0IFRlc3Qx
FDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvbcWtHXLwcr7ZDFXUjAV/dqTWfWY/QKLwTyHb+n8u9hpaEtAUUjKoqZc
aoFVbeQZgAyQdLU7fvWLu/H6IgrNMCCmGmVjlD/ZoWB4gTmzaOxf/rMiOwsMMcmo
s375pSxz+tRIReFEaBEAjHVKU36U0TDhOHYc030b2QWMEf1WgHyt9DqNAX5kMAFc
jfi8iZbuituXwZUJc3oHi2+77oSck9Xrfm7Kj8DfpyaNezTVZu5xV+uyGHUNT90w
RDyvD6+VjkcDkSAst1bWMmvhiTA0e5DhtOdWifKfTtJHMbgwlcgfIiGsqXr941d3
XsOx2pKmmoR2ZNSJlw3SxkdNXOKZ0QIDAQABoyAwHjALBgNVHQ8EBAMCAoQwDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAfyLFUkjm2zOnSyNWIbXL
/1kY17M2Gf+WizEKwa+CEMCFZYpITnYUrHzOHjJ6bTiV+FCAIR5hXTSLiGKiPiAD
2f1Jpc+k8celNVkPrJLIb9X99Q2orKFNwJHHUbCRpMIzCQfI4Rl/6KAWhZOZxebl
dXG4ZZAKSOupUN1l3zxW/RSCfiI3iiVisWLMaqrc1vR9bO7Hf9WncS2b7tEf41Dp
N2sWUdmtHZbRKFHEEWBZmUwFXH9TyOw+Fn39O1Jn/Mri33aarT86W1TI6+/xpTNi
dCD+qXTlu5XEl2ftuSFrpPrPh7pp9FGfIz/ae7Fgt6wbMsjwYwwHdjbrM5Sde8EY
zQ==
-----END CERTIFICATE-----
`,
		PrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9txa0dcvByvtk
MVdSMBX92pNZ9Zj9AovBPIdv6fy72GloS0BRSMqiplxqgVVt5BmADJB0tTt+9Yu7
8foiCs0wIKYaZWOUP9mhYHiBObNo7F/+syI7CwwxyaizfvmlLHP61EhF4URoEQCM
dUpTfpTRMOE4dhzTfRvZBYwR/VaAfK30Oo0BfmQwAVyN+LyJlu6K25fBlQlzegeL
b7vuhJyT1et+bsqPwN+nJo17NNVm7nFX67IYdQ1P3TBEPK8Pr5WORwORICy3VtYy
a+GJMDR7kOG051aJ8p9O0kcxuDCVyB8iIaypev3jV3dew7HakqaahHZk1ImXDdLG
R01c4pnRAgMBAAECggEAbxZRVjQPrpdT4tQ9hGOhzPZ7B9cW0Tf3a5ws1ixWEAxl
lGtT6wTLmrf9L2QyCNni0KcKwzwH7YyMWO4VAHAAvCix+ozZ5UoJ/kPF7C1ET7Dx
eOudpKMQberePNSiC8Te2MYK19hTPPiPsK9RaViafW+4wV3v/Sqp7scfwLzuNOdK
fqQrAyUVe40nTpsac407RZ9G8SJC8PPfc4muB45YH6C5GpQNkpFPlX1TVZ54gRgC
f/N9EvZz5pcnWg7kjAiPRaEx6S5eZ1OCKICk3V8Xt54L3P9TiIUGwPcC9eOhToGm
KKKhEgpK1pBuNmqHKWxjPv4VEwg0ru2NL3SXQmCC/QKBgQDmj6GXfbV1Ox5yeC6t
RwMAbFt5hYTtsHutUNGHmP8Y31y+mjN8Rz8iQV5NfHiw7IH9WBDidp6diGN1JD4x
/FKFlY+azK1M0qeHcRBbEKMGtkfZorsFn4H25Hhw4nDbjOtSS/FFenPLDcA6bySm
VkDGGCJGex94k37K5/Uc0zhrTwKBgQDSpbxIyyhKlCOfx0Fj53Xs1SYn4M8PFdlH
afs1NoupHb4unFLkuvm108thPmXOMsKeXFCkFLBcA0EKhZypLZz9F2FFAh0Z/Ip5
SG1BHnWz8lRbDtzvJzWQclFTT8088CIkDuhMTvQBw2rKY55XNpDHt6EdRfqUjU6M
SbZj26jg3wKBgEV2pqe+rwn32s+AGAgKqgPZoaG2MXtvPYPVIpuo48p5mTavvK1H
xeSrLx9HThF34B4VB1lDhbxOmDB1z+s9axtmGRL5cYkAuoqa7OOS2psuFe2jEpe6
G+znnsXb40ayaT+tM67MGtDlfrHcRH185R0JrmHvvGaWgY/eXMHnfUsPAoGBAIje
hYuq7YAf51HPL07Ru07qZENvEDsWEDsVwtMdoPt+xu8URcw3LT+W4URLPe0QEGLD
SuaCRuFSf/VtQZCvgZz1jw8+w1f6PqN1iv/P4dzNbUBJVQbTrDsx/GOsq4eX5CcX
xJqohmWK6x2cQusaGlKan0YdDSdu9YWz853IwV9zAoGAIIGzQAX581j6ziBgJx78
ilZoRcK4IdDhPIji2rEhUWiudboAWq6ljtNcva7tFcdK1UmgBSosuApG0enly1UK
3MZJzZyW4HoGmLYI+FellWJhjm4l6oEOcvb7m0ksZUkcuJcIdZVoLWq77kZ87ofN
eT6Q43/gPKpGi5Sq1heGugQ=
-----END PRIVATE KEY-----
`,
	}},
}
