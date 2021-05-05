package contentsignature // import "github.com/mozilla-services/autograph/verifier/contentsignature"

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// ParseChain parses a PEM-encoded certificate chain.
//
// It parses the end entity/leaf then the intermediate then the root
// cert. It does not validate the certificates or the chain.
//
// It returns the slice of three certs or an empty slice and an error.
//
func ParseChain(chain []byte) (certs []*x509.Certificate, err error) {
	block, rest := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to PEM decode EE/leaf certificate from chain")
	}
	ee, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing EE/leaf certificate from chain: %w", err)
	}
	certs = append(certs, ee)

	// the second cert is the intermediate
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to PEM decode intermediate certificate from chain")
	}
	inter, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate from chain: %w", err)
	}
	certs = append(certs, inter)

	// the third and last cert is the root
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to PEM decode root certificate from chain")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate from chain: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("found trailing data after root certificate in chain")
	}
	certs = append(certs, root)
	return certs, nil
}

// verifyRoot checks that a root cert is:
//
// 1) self-signed
// 2) a CA
// 3) has the x509v3 Extentions for CodeSigning use
//
// and SHA2 sum of raw bytes matches the provided hex-encoded with
// optional colons rootHash param (as from openssl x509 -noout -text
// -fingerprint -sha256 -in ca.crt)
func verifyRoot(rootHash string, cert *x509.Certificate) error {
	// this is the last cert, it should be self signed
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return fmt.Errorf("subject does not match issuer, should be equal")
	}
	if !cert.IsCA {
		return fmt.Errorf("missing IS CA extension")
	}
	if rootHash == "" {
		return fmt.Errorf("rootHash must not be empty")
	}
	rhash := strings.Replace(rootHash, ":", "", -1)
	// We're configure to check the root hash matches expected value
	h := sha256.Sum256(cert.Raw)
	certHash := fmt.Sprintf("%X", h[:])
	if rhash != certHash {
		return fmt.Errorf("hash does not match expected root: expected=%s; got=%s", rhash, certHash)
	}
	hasCodeSigningExtension := false
	for _, ext := range cert.ExtKeyUsage {
		if ext == x509.ExtKeyUsageCodeSigning {
			hasCodeSigningExtension = true
			break
		}
	}
	if !hasCodeSigningExtension {
		return fmt.Errorf("missing codeSigning key usage extension")
	}
	return nil
}

// VerifyChain checks certs in a three certificate chain [EE, intermediate, root] are:
//
// 1) signed by their parent/issuer/the next cert in the chain or all verifyRoot checks for the root
// 2) valid for the current time i.e. cert NotBefore < current time < cert NotAfter
// 3) the chain follows name constraints and extended key usage as checked by x509 Certificate.Verify
//
func VerifyChain(rootHash string, certs []*x509.Certificate, currentTime time.Time) error {
	if len(certs) != 3 {
		return fmt.Errorf("can only verify 3 certificate chain, got %d certs", len(certs))
	}

	var (
		inters = x509.NewCertPool()
		roots  = x509.NewCertPool()
	)
	for i, cert := range certs {
		var (
			timeToExpiration = cert.NotAfter.Sub(currentTime)
			timeToValid      = cert.NotBefore.Sub(currentTime)
		)
		if timeToExpiration < -time.Nanosecond {
			return fmt.Errorf("Certificate %d %q expired: notAfter=%s",
				i, cert.Subject.CommonName, cert.NotAfter)
		}
		if timeToValid > time.Nanosecond {
			return fmt.Errorf("Certificate %d %q is not yet valid: notBefore=%s",
				i, cert.Subject.CommonName, cert.NotBefore)
		}
		switch i {
		case 2: // the last cert is the root
			err := verifyRoot(rootHash, cert)
			if err != nil {
				return fmt.Errorf("Certificate %d %q is root but fails validation: %w",
					i, cert.Subject.CommonName, err)
			}
			roots.AddCert(cert)
		case 1:
			inters.AddCert(cert)
			fallthrough // fall through to check intermediate is signed by root
		case 0:
			fallthrough // fall through to check leaf is signed by intermediate
		default:
			// check that cert is signed by parent
			err := cert.CheckSignatureFrom(certs[i+1])
			if err != nil {
				return fmt.Errorf("Certificate %d %q is not signed by parent certificate %d %q: %v",
					i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName, err)
			}
		}
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		CurrentTime:   currentTime,
	}
	_, err := certs[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("error verifying certificate chain: %w", err)
	}
	return nil
}

// Verify validates the signature and certificate chain of a content signature response
//
// It takes:
//
// input data
// a content signature metadata
// a PEM-encoded of the cert chain string
// a rootHash
//
// It parses the certificate chain, verifies input data using the end-entity certificate of the chain,
// then verifies the cert chain of trust maps to the signed data.
//
// It returns an error if it fails or nil on success.
//
func Verify(input, certChain []byte, signature, rootHash string) error {
	certs, err := ParseChain(certChain)
	if err != nil {
		return fmt.Errorf("Error parsing cert chain: %w", err)
	}
	// Get the public key from the end-entity (certs[0] is the end entity)
	key, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Cannot verify EE/leaf cert with non-ECDSA public key type: %T", key)
	}
	// parse the json signature
	sig, err := Unmarshal(signature)
	if err != nil {
		return fmt.Errorf("Error unmarshal content signature: %w", err)
	}
	// make a templated hash
	if !sig.VerifyData(input, key) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	err = VerifyChain(rootHash, certs, time.Now())
	if err != nil {
		return fmt.Errorf("Error verifying content signature certificate chain: %w", err)
	}
	return nil
}
