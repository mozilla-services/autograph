package xpi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"go.mozilla.org/cose"
)

func TestMakeEndEntity(t *testing.T) {
	// returns an initialized XPI signer
	initSigner := func(t *testing.T, testcaseid int) *XPISigner {
		testcase := validSignerConfigs[testcaseid]
		s, err := New(testcase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}
		return s
	}

	t.Run("should set CN and hash CN for DNSNames", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 3)

		for _, testid := range []string{
			"foo",
			"0000",
			"a0d7ccb3-214d-498b-b4aa-0e8fda9a7bf7",
			"NavratnePeniaze@NávratnéPeniaze.com",
			"foo-bar@baz",
		} {
			t.Run(fmt.Sprintf("for CN=%q", testid), func(t *testing.T) {
				t.Parallel()

				cndigest := sha256.Sum256([]byte(testid))
				dnsname := fmt.Sprintf("%x.%x.addons.mozilla.org", cndigest[:16], cndigest[16:])
				cert, _, err := s.MakeEndEntity(testid, nil)
				if err != nil {
					t.Fatal(err)
				}
				if cert.Subject.CommonName != testid {
					t.Fatalf("expected cert cn to match testid %q but got %q", testid, cert.Subject.CommonName)
				}
				if len(cert.DNSNames) != 1 {
					t.Fatalf("expected to find 1 SAN entry but found %d", len(cert.DNSNames))
				}
				if cert.DNSNames[0] != dnsname {
					t.Fatalf("expected SAN to match testid %q but got %q", testid, cert.DNSNames[0])
				}
			})
		}
	})

	t.Run("should error for issuer priv (RSA) and pub key (nil) type mismatch - PKCS7 only", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 0)

		cn := "foo"
		if _, ok := s.issuerKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("expected RSA privateKey to test COSEKeyPair generation got %T", s.issuerKey)
		}
		s.issuerPublicKey = nil

		_, _, err := s.MakeEndEntity(cn, nil)
		if err == nil {
			t.Fatalf("expected MakeEndEntity to fail for mismatched issuer priv (%T) and pub key (%T) types", s.issuerKey, s.issuerPublicKey)
		}
	})

	t.Run("should error for issuer priv (RSA) and pub key (nil) type mismatch - COSE PS256", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 0)

		cn := "foo"
		if _, ok := s.issuerKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("expected RSA privateKey to test COSEKeyPair generation got %T", s.issuerKey)
		}
		s.issuerPublicKey = nil

		_, _, err := s.MakeEndEntity(cn, cose.PS256)
		if err == nil {
			t.Fatalf("expected MakeEndEntity to fail for mismatched issuer priv (%T) and pub key (%T) types", s.issuerKey, s.issuerPublicKey)
		}
	})

	t.Run("should set EE NotBefore to UTC now", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 3)

		testid := "foo"
		cert, _, err := s.MakeEndEntity(testid, nil)
		if err != nil {
			t.Fatal(err)
		}
		timeSinceNotBefore := time.Now().UTC().Sub(cert.NotBefore)
		if timeSinceNotBefore.Seconds() <= 0 {
			t.Fatalf("cert is not yet valid; got %f seconds since EE NotBefore", timeSinceNotBefore.Seconds())
		}
		// see GH #739 for details
		if timeSinceNotBefore.Minutes() > 5 {
			t.Fatalf("more than five minutes since cert; got %f seconds since EE NotBefore", timeSinceNotBefore.Seconds())
		}
	})
}

func TestGetIssuerRSAKeySize(t *testing.T) {
	// returns an initialized XPI signer
	initSigner := func(t *testing.T, testcaseid int) *XPISigner {
		testcase := validSignerConfigs[testcaseid]
		s, err := New(testcase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}
		return s
	}

	t.Run("should return the pubkey size", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 0)
		if _, ok := s.issuerKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("expected RSA privateKey to test getIssuerRSAKeySize got %T", s.issuerKey)
		}

		size, err := s.getIssuerRSAKeySize()
		if err != nil {
			t.Fatalf("unexpected err from getIssuerRSAKeySize %q", err)
		}
		if size != 4096 {
			t.Fatalf("got unexpected size from getIssuerRSAKeySize %d expected 2048", size)
		}
	})

	t.Run("should error for wrong public key type", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 0)
		if _, ok := s.issuerKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("expected RSA privateKey to test getIssuerRSAKeySize got %T", s.issuerKey)
		}
		s.issuerPublicKey = nil
		_, err := s.getIssuerRSAKeySize()
		if err == nil {
			t.Fatalf("did not get err from getIssuerRSAKeySize")
		}
	})
}

func TestGetIssuerECDSACurve(t *testing.T) {
	// returns an initialized XPI signer
	initSigner := func(t *testing.T, testcaseid int) *XPISigner {
		testcase := validSignerConfigs[testcaseid]
		s, err := New(testcase, nil)
		if err != nil {
			t.Fatalf("signer initialization failed with: %v", err)
		}
		return s
	}

	t.Run("should return the pubkey curve", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 3)

		if _, ok := s.issuerKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("expected EC privateKey to test getIssuerRSAKeySize got %T", s.issuerKey)
		}

		curve, err := s.getIssuerECDSACurve()
		if err != nil {
			t.Fatalf("unexpected err from getIssuerECDSACurve %q", err)
		}
		if curve != elliptic.P384() {
			t.Fatalf("got unexpected curve from getIssuerECDSACurve %q expected P384", curve)
		}
	})

	t.Run("should error for wrong public key type", func(t *testing.T) {
		t.Parallel()

		s := initSigner(t, 3)
		if _, ok := s.issuerKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("expected EC privateKey to test getIssuerECDSACurve got %T", s.issuerKey)
		}
		s.issuerPublicKey = nil
		_, err := s.getIssuerECDSACurve()
		if err == nil {
			t.Fatalf("did not get err from getIssuerECDSACurve")
		}
	})

}
