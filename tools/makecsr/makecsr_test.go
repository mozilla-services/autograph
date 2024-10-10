package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestGoldenPath(t *testing.T) {
	testcases := []struct {
		privKey       crypto.PrivateKey
		orgUnit       string
		commonName    string
		email         string
		dnsNames      []string
		sigAlg        x509.SignatureAlgorithm
		expectedError error
	}{
		{generateRSAKey(t), "MozOrg", "MozCN", "", []string{"example.com", "biff.com"}, x509.SHA256WithRSA, nil},
		{generateRSAKey(t), "MozOrg", "MozCN", "", []string{"okay.com"}, x509.SHA384WithRSA, nil},
		{generateRSAKey(t), "MozOrg", "MozCN/email=foobar.com", "", []string{"okay.com"}, x509.SHA256WithRSA, nil},
		{generateRSAKey(t), "MozOrg", "MozCN", "welp@foobar.com", []string{"okay.com"}, x509.SHA256WithRSA, nil},
		{generateECDSAKey(t), "Foo", "foocN", "", []string{"okay.com"}, x509.ECDSAWithSHA256, nil},
		{generateECDSAKey(t), "Foo", "foocN", "", []string{"okay.com"}, x509.ECDSAWithSHA384, nil},
		{generateRSAKey(t), "MozOrg", "MozCN", "", []string{"failed.com"}, x509.ECDSAWithSHA256, errors.New("x509: requested SignatureAlgorithm does not match private key type")},
	}
	for i, tc := range testcases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			out, err := generatePEMEncodedCSR(tc.privKey, tc.orgUnit, tc.commonName, tc.email, tc.dnsNames, tc.sigAlg)
			if tc.expectedError != nil {
				if err == nil {
					t.Fatalf("expectedError: want %v, got nil", tc.expectedError)
				}

				if !errors.Is(err, tc.expectedError) && !strings.Contains(err.Error(), tc.expectedError.Error()) {
					t.Fatalf("expectedError: want %v, got %v", tc.expectedError, err)
				}

				// return early because there's no valid `out` value to check
				return
			}
			if err != nil {
				t.Fatalf("unexpected generatePEMEncodedCSR error: %v", err)
			}

			csrBytes, rest := pem.Decode(out)
			if len(rest) != 0 {
				t.Fatalf("unexpected trailing data: %v", rest)
			}

			csr, err := x509.ParseCertificateRequest(csrBytes.Bytes)
			if err != nil {
				t.Fatalf("unexpected x509.ParseCertificateRequest error: %v", err)
			}
			t.Logf("csr pem:\n%s", out)
			if csr.Subject.CommonName != tc.commonName {
				t.Errorf("want CommonName %q, got %q", tc.commonName, csr.Subject.CommonName)
			}
			if len(csr.Subject.OrganizationalUnit) != 1 || csr.Subject.OrganizationalUnit[0] != tc.orgUnit {
				t.Errorf("want OrganizationalUnit %q, got %q", []string{tc.orgUnit}, csr.Subject.OrganizationalUnit[0])
			}
			if tc.email == "" {
				if len(csr.EmailAddresses) != 0 {
					t.Errorf("want no EmailAddresses, got %q", csr.EmailAddresses)
				}
			} else if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != tc.email {
				t.Errorf("want EmailAddresses %q, got %q", []string{tc.email}, csr.EmailAddresses)
			}
			if csr.Subject.Country[0] != "US" {
				t.Errorf("want Country %q, got %q", "US", csr.Subject.Country[0])
			}
			if !slices.Equal(csr.DNSNames, tc.dnsNames) {
				t.Errorf("want DNSNames %q, got %q", tc.dnsNames, csr.DNSNames)
			}
		})
	}
}

func generateRSAKey(t *testing.T) crypto.PrivateKey {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected rsa.GenerateKey error: %v", err)
	}
	return privKey
}

func generateECDSAKey(t *testing.T) crypto.PrivateKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unexpected ecdsa.GenerateKey error: %v", err)
	}
	return privKey
}
