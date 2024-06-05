package xpi

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/mozilla-services/autograph/signer"
	"go.mozilla.org/cose"
)

// mustParseTime is a test helper that parses an RFC3339 timestamp
// (e.g. "2006-01-02T15:04:05Z") or panics
func mustParseTime(rfc3339Timestamp string) time.Time {
	parsed, err := time.Parse(time.RFC3339, rfc3339Timestamp)
	if err != nil {
		log.Fatalf("error parsing timestamp %q: %q", rfc3339Timestamp, err)
	}
	return parsed
}

func TestStringToCOSEAlg(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input  string
		result *cose.Algorithm
	}{
		{input: "ES256", result: cose.ES256},
		{input: "es384", result: cose.ES384},
		{input: "Es512", result: cose.ES512},
		{input: "PS256", result: cose.PS256},
		{input: " PS256", result: nil},
		{input: "PS256!", result: nil},
	}

	for _, testcase := range cases {
		result := stringToCOSEAlg(testcase.input)
		if result != testcase.result {
			t.Fatalf("stringToCOSEAlg returned %v but expected %v", result, testcase.result)
		}
	}
}

func TestIntToCOSEAlg(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input  int
		result *cose.Algorithm
	}{
		{input: cose.ES256.Value, result: cose.ES256},
		{input: cose.ES384.Value, result: cose.ES384},
		{input: cose.ES512.Value, result: cose.ES512},
		{input: cose.PS256.Value, result: cose.PS256},
		{input: -1, result: nil},
		{input: 0, result: nil},
	}

	for _, testcase := range cases {
		result := intToCOSEAlg(testcase.input)
		if result != testcase.result {
			t.Fatalf("intToCOSEAlg returned %v but expected %v", result, testcase.result)
		}
	}
}

func TestGenerateCOSEKeyPair(t *testing.T) {
	// returns an initialized XPI signer
	initSigner := func(t *testing.T) *XPISigner {
		testcase := validSignerConfigs[0]
		s, err := New(testcase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}
		return s
	}

	t.Run("should error for nil COSE algorithm", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t)
		_, _, err := s.generateCOSEKeyPair(nil)
		if err == nil {
			t.Fatalf("didn't error generating keypair for nil COSE Algorithm got: %v instead", err)
		}
	})

	t.Run("should error for valid but unsupported COSE algorithm", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t)
		_, _, err := s.generateCOSEKeyPair(&cose.Algorithm{
			Name:  "EdDSA", // EdDSA from [RFC8152]
			Value: -8,
		})
		if err == nil {
			t.Fatalf("didn't error generating keypair for nil COSE Algorithm got: %v instead", err)
		}
	})

	t.Run("should error for nil issuerPublicKey", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t)
		s.issuerPublicKey = nil
		_, _, err := s.generateCOSEKeyPair(cose.PS256)
		if err == nil {
			t.Fatalf("didn't error generating key pair nil signer.issuerKey got: %v instead", err)
		}
	})

	t.Run("should error for string issuer key", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t)
		s.issuerPublicKey = "bad non-nil key type"
		_, _, err := s.generateCOSEKeyPair(cose.PS256)
		if err == nil {
			t.Fatalf("didn't error generating RSA key pair from string issuer")
		}
	})

	t.Run("should generate ES256 EE key for ECDSA intermediate", func(t *testing.T) {
		t.Parallel()

		coseSigner, err := cose.NewSigner(cose.ES256, nil)
		if err != nil {
			t.Fatalf("failed to generate ES256 key got error: %v", err)
		}

		s := initSigner(t)
		s.issuerKey = coseSigner.PrivateKey
		if _, ok := s.issuerKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("Failed to generate an ecdsa privateKey to test COSEKeyPair generation")
		}
		eeKey, _, err := s.generateCOSEKeyPair(cose.ES256)
		if err != nil {
			t.Fatalf("failed to generate ECDSA EE key pair from ECDSA issuer got: %v instead", err)
		}
		if _, ok := eeKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("failed to generate ECDSA EE key pair from ECDSA issuer got type: %T instead", eeKey)
		}
	})

	t.Run("should generate PS256 EE key for RSA intermediate", func(t *testing.T) {
		t.Parallel()

		coseSigner, err := cose.NewSigner(cose.PS256, nil)
		if err != nil {
			t.Fatalf("failed to generate PS256 key got error: %v", err)
		}

		s := initSigner(t)
		s.issuerKey = coseSigner.PrivateKey
		if _, ok := s.issuerKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("Failed to generate an RSA privateKey to test COSEKeyPair generation")
		}
		eeKey, _, err := s.generateCOSEKeyPair(cose.PS256)
		if err != nil {
			t.Fatalf("failed to generate RSA EE key pair from RSA issuer got: %v instead", err)
		}
		rsaKey, ok := eeKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("failed to generate RSA EE key pair from RSA issuer got type: %T instead", eeKey)
		}
		issuerKeySize, err := s.getIssuerRSAKeySize()
		if err != nil {
			t.Fatalf("failed to get issuer RSA key size: %q", err)
		}
		if rsaKey.N.BitLen() < issuerKeySize {
			t.Fatalf("EE key %d is smaller than signer issuer key %d", rsaKey.N.BitLen(), issuerKeySize)
		}
	})

	t.Run("should generate PS256 EE key of default size for ECDSA intermediate", func(t *testing.T) {
		t.Parallel()

		coseSigner, err := cose.NewSigner(cose.ES256, nil)
		if err != nil {
			t.Fatalf("failed to generate ES256 key got error: %v", err)
		}

		s := initSigner(t)
		s.issuerKey = coseSigner.PrivateKey
		if _, ok := s.issuerKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("Failed to generate an ECDSA privateKey to test COSEKeyPair generation")
		}
		s.issuerPublicKey = coseSigner.PrivateKey.(*ecdsa.PrivateKey).Public()
		eeKey, _, err := s.generateCOSEKeyPair(cose.PS256)
		if err != nil {
			t.Fatalf("failed to generate RSA EE key pair from ECDSA issuer got: %v instead", err)
		}
		rsaKey, ok := eeKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("failed to generate RSA EE key pair from ECDSA issuer got type: %T instead", eeKey)
		}
		if rsaKey.N.BitLen() < rsaKeyMinSize {
			t.Fatalf("EE key %d is smaller than default key size %d", rsaKey.N.BitLen(), rsaKeyMinSize)
		}
	})
}

func TestIsValidCOSESignatureErrs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input   *cose.Signature
		results []string
	}{
		//0
		{
			input:   nil,
			results: []string{"xpi: cannot validate nil COSE Signature"},
		},
		//1
		{
			input:   &cose.Signature{},
			results: []string{"xpi: got unexpected COSE Signature headers: xpi: cannot compare nil COSE headers"},
		},
		//2
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{"foo": 2},
				},
			},
			results: []string{"xpi: got unexpected COSE Signature headers: xpi: unexpected non-empty Unprotected headers got: map[foo:2]"},
		},
		//3
		{
			input: &cose.Signature{
				Headers: &cose.Headers{},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: unexpected Protected headers got: map[] expected: map[1:<nil> 4:<nil>]",
				"xpi: got unexpected COSE Signature headers: xpi: unexpected Protected headers got: map[] expected: map[4:<nil> 1:<nil>]"},
		},
		//4
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						"foo": 2,
						"bar": 1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: missing expected alg in Protected Headers",
			},
		},
		//5
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: nil,
						"bar":          1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: alg <nil> is not supported",
			},
		},
		//6
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: 2,
						"bar":          1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: alg 2 is not supported",
			},
		},
		//7
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: cose.ES256.Value,
						"bar":          1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: missing expected kid in Protected Headers",
				"xpi: COSE Signature kid value is not a byte array",
			},
		},
		//8
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: cose.ES256.Value,
						kidHeaderValue: "foo",
					},
				},
			},
			results: []string{
				"xpi: COSE Signature kid value is not a byte array",
				"xpi: failed to parse X509 EE certificate from COSE Signature: asn1: structure error: tags don't match",
				"xpi: failed to parse X509 EE certificate from COSE Signature: x509: malformed certificate",
			},
		},
		//9
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: cose.ES256.Value,
						kidHeaderValue: []byte("OK"),
					},
				},
			},
			results: []string{
				"xpi: failed to parse X509 EE certificate from COSE Signature: asn1: structure error: tags don't match",
				"xpi: failed to parse X509 EE certificate from COSE Signature: x509: malformed certificate",
			},
		},
	}

	for i, testcase := range cases {
		_, _, err := validateCOSESignatureStructureAndGetEECertAndAlg(testcase.input)
		anyMatches := false
		for _, result := range testcase.results {
			if strings.HasPrefix(err.Error(), result) {
				anyMatches = true
			}
		}
		if !anyMatches {
			t.Fatalf("validateCOSESignatureStructureAndGetEECertAndAlg case %d returned '%v'", i, err)
		}
	}
}

func TestIsValidCOSEMessageErrs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input   *cose.SignMessage
		results []string
	}{
		//0
		{
			input:   nil,
			results: []string{"xpi: cannot validate nil COSE SignMessage"},
		},
		//1
		{
			input:   &cose.SignMessage{Payload: []byte("not nil!")},
			results: []string{"xpi: expected SignMessage payload to be nil, but got [110 111 116 32 110 105 108 33]"},
		},
		//2
		{
			input:   &cose.SignMessage{Payload: nil},
			results: []string{"xpi: got unexpected COSE SignMessage headers: xpi: cannot compare nil COSE headers"},
		},
		//3
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: nil,
					},
				},
			},
			results: []string{
				"xpi: expected SignMessage Protected Headers kid value to be an array got <nil> with type <nil>",
				"xpi: expected SignMessage Protected Headers kid value 0 to be a byte slice got <nil> with type <nil>",
			},
		},
		//4
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: []interface{}{
							nil,
						},
					},
				},
			},
			results: []string{
				"xpi: expected SignMessage Protected Headers kid value 0 to be a byte slice got <nil> with type <nil>",
				"xpi: SignMessage Signature Protected Headers kid value 0 does not decode to a parseable X509 cert: asn1: structure error: tags don't match",
				"xpi: SignMessage Signature Protected Headers kid value 0 does not decode to a parseable X509 cert: x509: malformed certificate",
			},
		},
		//5
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: []interface{}{
							[]byte("not a cert"),
						},
					},
				},
			},
			results: []string{
				"xpi: SignMessage Signature Protected Headers kid value 0 does not decode to a parseable X509 cert: asn1: structure error: tags don't match",
				"xpi: SignMessage Signature Protected Headers kid value 0 does not decode to a parseable X509 cert: x509: malformed certificate",
			},
		},
		//6
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: []interface{}{},
					},
				},
				Signatures: []cose.Signature{
					cose.Signature{},
				},
			},
			results: []string{"xpi: cose signature 0 is invalid: xpi: got unexpected COSE Signature headers: xpi: cannot compare nil COSE headers"},
		},
	}

	for i, testcase := range cases {
		_, _, _, err := validateCOSEMessageStructureAndGetCertsAndAlgs(testcase.input)

		anyMatches := false
		for _, result := range testcase.results {
			if strings.HasPrefix(err.Error(), result) {
				anyMatches = true
			}
		}
		if !anyMatches {
			t.Fatalf("validateCOSEMessageStructureAndGetCertsAndAlgs case %d returned '%v'", i, err)
		}
	}
}

func mustPackJAR(t *testing.T, metafiles []Metafile) []byte {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	for _, file := range metafiles {
		fwhead := &zip.FileHeader{
			Name:   file.Name,
			Method: zip.Deflate,
		}
		fw, err := w.CreateHeader(fwhead)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fw.Write(file.Body)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := w.Close()
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestVerifyCOSESignaturesErrs(t *testing.T) {
	t.Parallel()

	expiredSigBytes, err := hex.DecodeString(strings.Replace(expiredCOSESig, "\n", "", -1))
	if err != nil {
		t.Fatalf("error decoding validCOSESig %q", err)
	}

	validSigBytes, err := hex.DecodeString(strings.Replace(validCOSESig, "\n", "", -1))
	if err != nil {
		t.Fatalf("error decoding expiredCOSESig %q", err)
	}

	msgBytes, err := cose.Unmarshal(validSigBytes)
	if err != nil {
		t.Fatalf("error unmarshaling validCOSESig %q", err)
	}
	msg := msgBytes.(cose.SignMessage)
	msg.Payload = []byte("blah")

	invalidSigBytes, err := cose.Marshal(msg)
	if err != nil {
		t.Fatalf("error unmarshaling invalidSigBytes %q", err)
	}

	s, err := New(validSignerConfigs[0], nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %q", err)
	}
	testCNValidSig, err := s.issueCOSESignature("test-cn", []byte("foo"), []*cose.Algorithm{cose.ES256})
	if err != nil {
		t.Fatalf("signer failed to issuer test COSE Signature with err: %q", err)
	}

	testCNRoots := x509.NewCertPool()
	ok := testCNRoots.AppendCertsFromPEM([]byte(validSignerConfigs[0].Certificate))
	if !ok {
		t.Fatalf("failed to add root cert to pool")
	}

	cases := []struct {
		name             string
		verificationTime time.Time
		fin              signer.SignedFile
		roots            *x509.CertPool
		opts             Options
		results          []string
	}{
		{
			name:             "invalid empty zip",
			verificationTime: time.Now().UTC(),
			fin:              nil,
			roots:            nil,
			opts:             Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
			results: []string{
				"xpi: failed to read META-INF/cose.manifest from signed zip: error reading ZIP: zip: not a valid zip file",
			},
		},
		{
			name:             "invalid non-empty zip",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte("foo"),
				},
			}),
			roots: nil,
			opts:  Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
			results: []string{
				"xpi: failed to read META-INF/cose.sig from signed zip: failed to find \"META-INF/cose.sig\" in ZIP",
			},
		},
		{
			name:             "invalid zip missing META-INF/manifest.mf",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte("foo"),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: []byte("foo"),
				},
			}),
			roots: nil,
			opts:  Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
			results: []string{
				"xpi: failed to read META-INF/manifest.mf from signed zip: failed to find \"META-INF/manifest.mf\" in ZIP",
			},
		},
		{
			name:             "invalid pkcs7 manifest",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte("foo"),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: []byte("foo"),
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("foo"),
				},
			}),
			roots: nil,
			opts:  Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
			results: []string{
				"xpi: pkcs7 manifest does not contain the line: \"Name: META-INF/cose.sig\"",
			},
		},
		{
			// cose sig should include pk7 sig and not the other way around
			name:             "cose.sig in pkcs7 manifest",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte("Name: META-INF/cose.sig"),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: []byte("foo"),
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: nil,
			opts:  Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
			results: []string{
				"xpi: cose manifest contains the line: \"Name: META-INF/cose.sig\"",
			},
		},
		{
			name:             "invalid cose.sig",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: []byte("foo"),
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: nil,
			opts:  Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
			results: []string{
				"xpi: error unmarshaling cose.sig: xpi.Unmarshal: failed to parse pkcs7 signature: ber2der: BER tag length is more than available data",
			},
		},
		{
			name:             "cose.sig missing second signature",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: validSigBytes,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: nil,
			opts: Options{
				ID:             "ffffffff-ffff-ffff-ffff-ffffffffffff",
				COSEAlgorithms: []string{"ES256", "PS256"},
			},
			results: []string{
				"xpi: cose.sig contains 1 signatures, but expected 2",
			},
		},
		{
			name:             "invalid cose.sig SignMessage",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: invalidSigBytes,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: nil,
			opts: Options{
				ID:             "ffffffff-ffff-ffff-ffff-ffffffffffff",
				COSEAlgorithms: []string{"ES256"},
			},
			results: []string{
				"xpi: cose.sig is not a valid COSE SignMessage: xpi: expected SignMessage payload to be nil, but got [98 108 97 104]",
			},
		},
		{
			name:             "cose.sig addon ID with mismatched EE cert CN",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: validSigBytes,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: nil,
			opts: Options{
				ID:             "foo",
				COSEAlgorithms: []string{"ES256"},
			},
			results: []string{
				"xpi: EECert 0: id \"foo\" does not match cert cn \"jid1-Kt2kYYgi32zPuw@jetpack\"",
			},
		},
		{
			name:             "missing root cert",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: validSigBytes,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: nil,
			opts: Options{
				ID:             "jid1-Kt2kYYgi32zPuw@jetpack",
				COSEAlgorithms: []string{"ES256"},
			},
			results: []string{
				"xpi: failed to verify EECert 0: x509: certificate signed by unknown authority",
			},
		},
		{
			name:             "expired COSE sig with invalid EC data verified for now errors",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: expiredSigBytes,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: testCNRoots,
			opts: Options{
				ID:             "jid1-Kt2kYYgi32zPuw@jetpack",
				COSEAlgorithms: []string{"ES256"},
			},
			results: []string{
				"xpi: failed to verify EECert 0: x509: certificate has expired or is not yet valid:",
			},
		},
		{
			name:             "expired COSE sig with invalid EC data verified at valid time errs for invalid name",
			verificationTime: mustParseTime("2019-01-01T15:04:05Z"),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte(""),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: expiredSigBytes,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: testCNRoots,
			opts: Options{
				ID:             "jid1-Kt2kYYgi32zPuw@jetpack",
				COSEAlgorithms: []string{"ES256"},
			},
			results: []string{
				"xpi: failed to verify EECert 0: x509: certificate is not valid for any names, but wanted to match a8a90aed72f6c28ac9cb723415558705.464b67e6be7d5509503eb06792f51426.addons.mozilla.org",
			},
		},
		{
			name:             "invalid EC data",
			verificationTime: time.Now().UTC(),
			fin: mustPackJAR(t, []Metafile{
				Metafile{
					Name: "META-INF/cose.manifest",
					Body: []byte("bad manifest"),
				},
				Metafile{
					Name: "META-INF/cose.sig",
					Body: testCNValidSig,
				},
				Metafile{
					Name: "META-INF/manifest.mf",
					Body: []byte("Name: META-INF/cose.sig\nName: META-INF/cose.manifest"),
				},
			}),
			roots: testCNRoots,
			opts: Options{
				ID:             "test-cn",
				COSEAlgorithms: []string{"ES256"},
			},
			results: []string{
				"xpi: failed to verify COSE SignMessage Signatures: verification failed ecdsa.Verify",
			},
		},
	}

	for i, testcase := range cases {
		err := verifyCOSESignatures(testcase.fin, testcase.roots, testcase.opts, testcase.verificationTime)
		anyMatches := false
		for _, result := range testcase.results {
			if strings.HasPrefix(err.Error(), result) {
				anyMatches = true
			}
		}
		if !anyMatches {
			t.Fatalf("verifyCOSESignatures case %q (%d) returned '%v' expected a prefix from %q", testcase.name, i, err, testcase.results)
		}
	}
}

func TestIssueCOSESignatureErrs(t *testing.T) {
	t.Parallel()

	signer, err := New(validSignerConfigs[0], nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}

	signer.issuerCert.Raw = []byte("")
	_, err = signer.issueCOSESignature("cn", []byte("manifest"), []*cose.Algorithm{cose.ES256})
	if err == nil {
		t.Fatalf("issueCOSESignature did not error on empty signer.issuerCert.Raw")
	}

	signer.issuerCert = nil
	_, err = signer.issueCOSESignature("cn", []byte("manifest"), []*cose.Algorithm{cose.ES256})
	if err == nil {
		t.Fatalf("issueCOSESignature did not error on nil signer.issuerCert")
	}

	signer = nil
	_, err = signer.issueCOSESignature("cn", []byte("manifest"), []*cose.Algorithm{cose.ES256})
	if err == nil {
		t.Fatalf("issueCOSESignature did not error on nil signer")
	}
}

// expiredCOSESig is a stage signed COSE SignMessage with one ES256
// signature that expired on 2019-06-06
const expiredCOSESig = `
d8628459076da10481590767308207633082054ba0030201020204010000
03300d06092a864886f70d01010b05003081a8310b300906035504061302
5553310b3009060355040813024341311630140603550407130d4d6f756e
7461696e2056696577311c301a060355040a13134164646f6e7320546573
74205369676e696e67312430220603550403131b746573742e6164646f6e
732e7369676e696e672e726f6f742e63613130302e06092a864886f70d01
090116216f707365632b7374616765726f6f746164646f6e73406d6f7a69
6c6c612e636f6d301e170d3137303530333139323733395a170d32353032
30373135323835315a308183310b3009060355040613025553310b300906
0355040813024341311c301a060355040a13134164646f6e732054657374
205369676e696e67312630240603550403131d73746167696e676361312e
6164646f6e732e616c6c697a6f6d2e6f72673121301f06092a864886f70d
0109011612666f78736563406d6f7a696c6c612e636f6d30820222300d06
092a864886f70d01010105000382020f003082020a0282020100cb08d622
4bb867e88953609b4edac78ec98bf252fcfd8cef74d974fd50239b38321f
52b79e000359deb9ceeafa5227d9712cdef37352d267a4526d50c97c9599
96208e4bbdc4d62fbdebd28dd2c9a06f665ae3e01b85869d077bcee0b0ff
c62979d5b3fdf940b5f2f74b7619f7d3aa79cfaffa98c643abc89a763bd1
04d1418ec5eb0bcd6fc7037995df41bbf19935177238f0da5c4cefeb2579
be5fe6c4ae1a3e115acda325416a31d98b85c5cb250cdd1ceccdda2fdfff
fc10fd54bf0b8c211f0a5e5ec16c4161aabf36bf39bc8bd5f8a066acb130
b53ab3f919ff81fda546885950ec39b5db9604370abda551adba980ad149
e9cc06e133af0410ee116f1ae02991a9c14553ec67e53fefec41ae2ea879
b50fe0df2965bfa0a7aeaf216dba84ffe34de8524a1a2bde173bf5415b3b
7ed33c2bb1896ab94f7b8d33b9cd1f1a294d22bdb7a125958eae0b640962
3a53f5ac6f925589363aabdcd0413eaf708af8bf413ecea69b345498cbaf
5f4e9d001619a8945d91344b2df82e3ce30ff1d4807f4560ea5b4e2f860f
7f70cc8b7304b53695bddd9ff0b3f933ddb606c503445cc4b0ea9890387c
2ab44627d8587e8eb68fcf81b40125e5e7cd9e64acea01c7344f2306c08a
77c81c264611d9fc0cc719860bebb795d63c1e67e93eac9034daa1111a82
d7c3988c58cc0ebf355c2abef69bc43d7caff0c8b2e23031070e34c30203
010001a38201b6308201b2300c0603551d13040530030101ff300e060355
1d0f0101ff04040302010630160603551d250101ff040c300a06082b0601
0505070303301d0603551d0e041604149758e93c6a29c94024d4550bb5a1
a2a7054f7af03081d50603551d230481cd3081ca801484ea5fcd6f4c922f
ead1f4f5c8a3b2c20cbaa6f6a181aea481ab3081a8310b30090603550406
13025553310b3009060355040813024341311630140603550407130d4d6f
756e7461696e2056696577311c301a060355040a13134164646f6e732054
657374205369676e696e67312430220603550403131b746573742e616464
6f6e732e7369676e696e672e726f6f742e63613130302e06092a864886f7
0d01090116216f707365632b7374616765726f6f746164646f6e73406d6f
7a696c6c612e636f6d820101303306096086480186f84201040426162468
7474703a2f2f6164646f6e732e616c6c697a6f6d2e6f72672f63612f6372
6c2e70656d304e0603551d1e04473045a1433020821e2e636f6e74656e74
2d7369676e61747572652e6d6f7a696c6c612e6f7267301f821d636f6e74
656e742d7369676e61747572652e6d6f7a696c6c612e6f7267300d06092a
864886f70d01010b05000382020100874d9824881304f27a89a277ee168f
8231f343eb564563a41d4086d6bde3d0d199be66a91379b8ef6361d60af4
7f4f4c4544bfb8132e37969ca36f8597eb299cfbc9691dc79e5e47dc4955
a7a6d4495d6a9b649e994d72bf5a320b8a3e00ae5889af87466eca4ee107
313140376d0cea261bf8d83e0c69b8394846e628be599c3c8195d1b268cb
4586c9b34bbbb41bf550ea7630da1e9e4327ac19b16927b9512637bc2917
5a97202b34429e4361baffb287e26682e9710e9a9db89e14547590256020
d39db7997eb49f803649df8567fcd8e99863718f782c04ebb7c8c78b7f30
06e27c6bf91d5aed10709d3b9d8cf976f6b09b32a4f798403e0bc85ff4a5
e8ca1f17498dae1cd044c2fa1bdd6baf05f7af71e20e35b681392dfc13fc
b532e961a688e46d92fc41e75025a57b869b1ff135ef041544254581e5fa
f4398c3b5c0aa8c1ac9de78a9dcd5dfc0e5775a09a7e5f7fb592f11c763f
e7be3441ada9a29328f4f795fc104d98b8b3b4e8d41d7e22eca62532c99c
6257d61c27f950751e548c43278c15ecc8c2df0bc5eca7f15bb282060ae4
0de09f644397fcaa6b7adafc288b18efdb8ae6d05982aec81584998c1268
c62e2ebccc04bd3c71fe5c03270a6e39ad21a83efbf024d2e61d732d1b36
a5cf34f569a671d895e85cd96be2b3294efff858e952ae31042b7d4605df
3eff3c5c3366f127a7dcd312cc5e5ce044a0f681835903f7a20126045903
f0308203ec308201d4a003020102020815359ac4a0c08fcb300d06092a86
4886f70d01010b0500308183310b3009060355040613025553310b300906
0355040813024341311c301a060355040a13134164646f6e732054657374
205369676e696e67312630240603550403131d73746167696e676361312e
6164646f6e732e616c6c697a6f6d2e6f72673121301f06092a864886f70d
0109011612666f78736563406d6f7a696c6c612e636f6d301e170d313830
3630363135313031375a170d3139303630363135313031375a307e310b30
09060355040613025553310b300906035504081302434131163014060355
0407130d4d6f756e7461696e2056696577310f300d060355040a13064164
646f6e7331133011060355040b130a50726f64756374696f6e3124302206
035504030c1b6a6964312d4b74326b5959676933327a507577406a657470
61636b3059301306072a8648ce3d020106082a8648ce3d03010703420004
86252f7b3ad3546508332ff3fea2231d51fc402cddc548a2c982ea7ea10d
1592bd88b4d6cf86981565fa6ddb174c764288f61219da6bae7d4fb303d6
a9beac9ca3333031300e0603551d0f0101ff040403020780301f0603551d
230418301680149758e93c6a29c94024d4550bb5a1a2a7054f7af0300d06
092a864886f70d01010b050003820201002365ec806245d05c43f0fde65b
aa4c7d285645b64fa21b562b0c0b42602a386529a80d8ccbe96761f9d750
6adcad3690f0a86b251d5aa2955ed1a006ab1167decfb0b8f6f9c0659de2
1455f5dadd768754e110ffcd8dba47037915191cdafb606ba63f276dcc4f
e4e88dc8aed80eebdbf08e3305c7422757dcf9b1dfd67351fba03a661755
57c82ebefed2ef397f886cfc363ef646fab5bfbb6c869649b3c8b33c8f5b
f2c6f0f7ef802ed47c66c1bf3b5331cb0067ca6ffeded4b9b717a0e9d887
a75598e4941c77aac67e06dce6c34c61b85513478a53c75ca7cb4630c7ec
7e679f932fc46a7fd09cbf5262a8e2a5b7a40b6fe182c090eb17be00f040
2b4ef0f72548602490e0bc1861e6dd4432842d67e2d92251ebc9927a54ea
f497a79dce178d6da8262c2d80b2e9071d2fb19cb23b0e854ccf7c611907
89441d765c4b2aabd1119918e48d384f3cc9ceedbcecc58600e7639e10e2
7968902cc678ef7287f737827df0360f229d5ba150dccf87c50bad9419f9
bd88fcfa892dd0d20f0d25f08acbd5a1429cbe3746ee0eb7f66983ab2926
e10ac6c34508417cd44f2566baefd4545f2103e11bd29567cd10b917560d
a1cfaf3be3e94d7ddee7d61581c3e2c14a1d142769f3d821d51b9f459b69
54586acd564ef1015207e277b41ff703ab91052eaaace03ea9ff0f4093fe
a4408b8603b184e8b587d132f6cdf2ffb83e54a05840572b5c9eedf8de68
1b8364f511c5d88d0bda2a0c5bc454e6d155bb4b5dd223aa0ccb271a81bf
aab7940071a3a8187052499ae6768b2e601da12b5e1869bd56ee`

// validCOSESig is a dev signed COSE SignMessage with one ES256
// signature
//
// to regen:
//
// go run client.go -f "pomodoro_clock-1.1.1-an+fx-windows.xpi" -u alice -p fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu -cn "jid1-Kt2kYYgi32zPuw@jetpack" -pk7digest sha256 -k "webextensions-rsa" -r dev-webext-rsa-root.pem -o signed-SHA2-ES256.zip -c "ES256"
// unzip signed-SHA2-ES256.zip
// xxd -p META-INF/cose.sig
const validCOSESig = `
d862845907dda104815907d7308207d3308205bba003020102020101300d
06092a864886f70d01010b05003081bc310b300906035504061302555331
0b3009060355040813024341311630140603550407130d4d6f756e746169
6e2056696577311c301a060355040a1313416c6c697a6f6d20436f72706f
726174696f6e3120301e060355040b1317416c6c697a6f6d20414d4f2044
6576656c6f706d656e74311830160603550403130f6465762e616d6f2e72
6f6f742e6361312e302c06092a864886f70d010901161f666f787365632b
646576616d6f726f6f746361406d6f7a696c6c612e636f6d301e170d3137
303332313233343430345a170d3237303331393233343430345a3081bc31
0b3009060355040613025553310b30090603550408130243413116301406
03550407130d4d6f756e7461696e2056696577311c301a060355040a1313
416c6c697a6f6d20436f72706f726174696f6e3120301e060355040b1317
416c6c697a6f6d20414d4f20446576656c6f706d656e7431183016060355
0403130f6465762e616d6f2e726f6f742e6361312e302c06092a864886f7
0d010901161f666f787365632b646576616d6f726f6f746361406d6f7a69
6c6c612e636f6d30820222300d06092a864886f70d01010105000382020f
003082020a0282020100c757e6ca14baf5a79151d11cde41281cab829b94
dd08a813c48d4fb0704457aa6cec9276fbb979c40074d52845b472166341
7adcb6ad033dab0eb2f1e49ef5fb9f220aefd6c83fc63eefc1e2e6b82f0e
6fece8e7f8b0450c382547579c38f05f75b46ae87441161fc5618ade156b
3fd8f5cc8264ff2441a2b9c2bd74ed9fc0bf855484fcf59ce82b95f2f4dc
a728fe4cf9e22efba5ab5ecd7655f9aa051d9f5ca8ba02719f39e4c27a08
68160b740c992492141289a2108c5f69b8e787cadf48c23002a9ac96b0bc
17bdf2a3826b0aa24fb758a98207e93b76408e51284cc713520caa47c077
e46caecb0591d17ae4255ecd03b04cd6a3632dbdada345d04ab1b2580eee
3f0f3c2ee564d9a50f0c4e6e34ae4abffffe4860a1527d9f0d94ec8e3dc9
298edfdfd255c21fe793c664029a659def1f28fa249d6edeaf647eade8f2
071d7e7c98cb7a0290b004e980acf82d17f872ddf8a16495e905eb67f28a
5be7eb5a81e7732f02f949c20b770304ab36ef6caa3af06818c413ac5e68
327f22fd16a98016c1770cac7495dbf9bb9fffe652d0f52dedabca148957
a823598c6df1a2d06c4ee08be7302854aa17256d45c2b719a6f790ba2b21
29635ff4877ed07681743a7fbe56eb4f05c3d73b317d8bd8c3cc08ecd90d
3b74d00678b98b21b8075c21a11f99e4079b5ae26a567b09ca33da90d8ae
84a36c3bfc536b84c5ff299f0203010001a38201dc308201d8300f060355
1d130101ff040530030101ff300e0603551d0f0101ff0404030201863016
0603551d250101ff040c300a06082b06010505070303301d0603551d0e04
160414d8b469a9375e435425056340e9f600a8776949a53081e90603551d
230481e13081de8014d8b469a9375e435425056340e9f600a8776949a5a1
81c2a481bf3081bc310b3009060355040613025553310b30090603550408
13024341311630140603550407130d4d6f756e7461696e2056696577311c
301a060355040a1313416c6c697a6f6d20436f72706f726174696f6e3120
301e060355040b1317416c6c697a6f6d20414d4f20446576656c6f706d65
6e74311830160603550403130f6465762e616d6f2e726f6f742e6361312e
302c06092a864886f70d010901161f666f787365632b646576616d6f726f
6f746361406d6f7a696c6c612e636f6d820101304206096086480186f842
01040435163368747470733a2f2f636f6e74656e742d7369676e61747572
652e6465762e6d6f7a6177732e6e65742f63612f63726c2e70656d304e06
082b0601050507010104423040303e06082b060105050730028632687474
70733a2f2f636f6e74656e742d7369676e61747572652e6465762e6d6f7a
6177732e6e65742f63612f63612e70656d300d06092a864886f70d01010b
05000382020100ba95b79e164e4c43e54e5f1cf45449903dac58a0a0872b
1cdaeafa04c3774e7b7010d458d7347041d5a9a3f4ce0cea0f66c8855fd6
5a57cc0d8dd59c1f0bdbe563beed8212df3ff4a879c7d22006666de5550c
b8476640ec87bc0ee5cf7508fa399419ca23b4bb22fac7f89310d9877401
dd3ff01a21e0f8aeef5e763b196132d428dfc24fddbdb4f63834dbe41dd2
3c6b21ef95667f314681eaf3b12ef52cde056014549252def28cea285f2b
fe3184daf7c34750b2d3da4da11f6d8becda06212d3255898f162bbfb1ef
ba80d1f712e63f1c95ea041ba3a3676ee764a4d760e4b85b637595d4880b
4e7c09eda1d7833399df0fd5b1272d8386de6598189ebf35bcb2b279f589
1f557309ee574e0c170b547f69f1a2549d0f840d7e4f8332f684da401b22
35803691e5ca25b4ca7ab313ba9a0b815fe5263c5f17905f422cbd34bd7c
fdbcf1a9ff89ef0e0fff8a07b77402748480221946e2db577d147ca33ea8
6c06fa4187427f7c7d6f6ff751729ddd427e8307213e38fa2279cb2bc8a0
f6c727e28a553640648e5311b2ad72774d7b790ccb4a2ae92a3ddbafaf6a
c8ba326ff9cf3498bb6cbd4a6dfea6e661791a6291f8696fabbe0ef2b2d0
6776bbe6fe87f8dc0ea809599d6489982f384761c7b073c1c3eda9131253
1396d172db5196111d378349daf5899ce1f40c4347cba4c4c00088349571
e9fb6e71f3dfbcec48a0f681835904a8a20126045904a13082049d308202
85a00302010202081629f6893b60067b300d06092a864886f70d01010b05
003081bc310b3009060355040613025553310b3009060355040813024341
311630140603550407130d4d6f756e7461696e2056696577311c301a0603
55040a1313416c6c697a6f6d20436f72706f726174696f6e3120301e0603
55040b1317416c6c697a6f6d20414d4f20446576656c6f706d656e743118
30160603550403130f6465762e616d6f2e726f6f742e6361312e302c0609
2a864886f70d010901161f666f787365632b646576616d6f726f6f746361
406d6f7a696c6c612e636f6d301e170d3230303831303136353635325a17
0d3330303830383136353635325a307e310b300906035504061302555331
0b3009060355040813024341311630140603550407130d4d6f756e746169
6e2056696577310f300d060355040a13064164646f6e7331133011060355
040b130a50726f64756374696f6e3124302206035504030c1b6a6964312d
4b74326b5959676933327a507577406a65747061636b3059301306072a86
48ce3d020106082a8648ce3d03010703420004777f2ea0e8b9a91da6a6c0
fda7d17b8f56c8dc73968e64413672610ca9fe95ad727da028700aa692b7
1779e224a2ad381714b54bf8646f3600bc63a5387e8bd6a381aa3081a730
0e0603551d0f0101ff04040302078030130603551d25040c300a06082b06
010505070303301f0603551d23041830168014d8b469a9375e4354250563
40e9f600a8776949a5305f0603551d110458305682546138613930616564
3732663663323861633963623732333431353535383730352e3436346236
3765366265376435353039353033656230363739326635313432362e6164
646f6e732e6d6f7a696c6c612e6f7267300d06092a864886f70d01010b05
000382020100c435f9bfdfd2fec868554a32d05876b95b2de438c29b171b
30ec1059d97d5d89dc22acfb243d31d3cea3039e19a22887e58c08464dcd
491cdb6f81a5ab4bec23c0c3dda50884b9c04ed3cfb663b46ee84e4539d0
383ebf37d2bbd9409f117e3ba8047cb04150758ee6bec3fcd1300816ee81
a9d4ba38d320af7174181c8285b2232ad1b999318c55d01de610689bc159
66bffcbd698e27e6e8279eb6cf9ce547da3671b4acf50dc76b99e721c7da
67e94961794bc024877512158da90ea8290d53f7e180ce55e112f02736f7
677b15548a809846cc4b14d20aa70193eaf2a2bb9e4f9c11081dd3c5380c
67b4dcf115ba46baedcd8ec927836533001ee4b5bb537122622ba20fa714
2e284fe0e33f58ccca7262db7252aa45dd19266e6fe80a2803c0bf265123
f5bacdf18b74d22f8359793aacd7e214604b7b486cbbe869e489da60e3df
b67fb0506b6fee71ce9927b169f9d67581f98527c21db0b835ad393330c3
b656fd473f56d9a02c1ac9a98221ad95e7bbdc4fdbb5ac7e4d54422f52e4
0c6161074667212fa6a086de6e3eeef9674189eeb7714ab6c0791bd29864
a21d4b07ccecfc77cdab39aec407d8f398710b81535e673dde9f937dbe70
28c56c04ef6b6406198f0f2a3ac1edfc76db5ae3e841102fe811c36dc5c0
271bc70d85a67e770927ae8d57796f680ca7aa29c4bbc4439d91a65987ff
a000b4963d2f14b4a058405c119295e5e8857851cfa7645e8393d7ab07f3
7ec34445e7b32d7ee1d50e6dad8eb92b25c060e66b1ea91237901e5a689d
a838ab76f8ad1ffe8893a64724c1ad`
