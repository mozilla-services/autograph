package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mozilla.org/autograph/signer/contentsignature"
)

// Certificates no longer in use but not yet removed from the autograph config.
// we don't want to alert on those.
// https://bugzilla.mozilla.org/show_bug.cgi?id=1466523
var ignoredCerts = map[string]bool{
	"fingerprinting-defenses.content-signature.mozilla.org": true,
	"fennec-dlc.content-signature.mozilla.org":              true,
	"focus-experiments.content-signature.mozilla.org":       true,
}

// validate the signature and certificate chain of a content signature response
//
// If an X5U value was provided, use the public key from the end entity certificate
// to verify the sig. Otherwise, use the PublicKey contained in the response.
//
// If the signature passes, verify the chain of trust maps.
func verifyContentSignature(response signatureresponse) error {
	var (
		key   *ecdsa.PublicKey
		err   error
		certs []*x509.Certificate
	)
	sig, err := contentsignature.Unmarshal(response.Signature)
	if err != nil {
		log.Fatal(err)
	}
	sig.X5U = response.X5U
	if sig.X5U != "" {
		certs, err = getX5U(sig.X5U)
		if err != nil {
			return err
		}
		if len(certs) < 2 {
			return fmt.Errorf("Found %d certs in X5U, expected at least 2", len(certs))
		}
		// certs[0] is the end entity
		key = certs[0].PublicKey.(*ecdsa.PublicKey)
	} else {
		key, err = parsePublicKeyFromB64(response.PublicKey)
		if err != nil {
			return err
		}
	}
	if !sig.VerifyData([]byte(inputdata), key) {
		return fmt.Errorf("Signature verification failed")
	}
	if certs != nil {
		err = verifyCertChain(certs)
		if err != nil {
			// check if we should ignore this cert
			if _, ok := ignoredCerts[certs[0].Subject.CommonName]; ok {
				return nil
			}
			return err
		}
	}
	return nil
}

func getX5U(x5u string) (certs []*x509.Certificate, err error) {
	log.Printf("Retrieving X5U %q", x5u)
	resp, err := http.Get(x5u)
	if err != nil {
		return certs, fmt.Errorf("Failed to retrieve X5U %s: %v", x5u, err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	// the first row must contain BEGIN CERT for the end entity
	scanner.Scan()
	if scanner.Text() != "-----BEGIN CERTIFICATE-----" {
		return certs, fmt.Errorf("Invalid X5U format for %s: first row isn't BEGIN CERTIFICATE", x5u)
	}
	var certPEM []byte
	certPEM = append(certPEM, scanner.Bytes()...)
	certPEM = append(certPEM, byte('\n'))
	for scanner.Scan() {
		certPEM = append(certPEM, scanner.Bytes()...)
		certPEM = append(certPEM, byte('\n'))
		if scanner.Text() == "-----END CERTIFICATE-----" {
			// end of the current cert. Parse it, store it
			// and move on to next cert
			block, _ := pem.Decode(certPEM)
			if block == nil {
				return certs, fmt.Errorf("Failed to parse certificate PEM")
			}
			certX509, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certs, fmt.Errorf("Could not parse X.509 certificate: %v", err)
			}
			log.Printf("Retrieved certificate CN=%q", certX509.Subject.CommonName)
			certs = append(certs, certX509)
			certPEM = nil
		}
	}
	return certs, nil
}

func parsePublicKeyFromB64(b64PubKey string) (pubkey *ecdsa.PublicKey, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(b64PubKey)
	if err != nil {
		return pubkey, fmt.Errorf("Failed to parse public key base64: %v", err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return pubkey, fmt.Errorf("Failed to parse public key DER: %v", err)
	}
	pubkey = keyInterface.(*ecdsa.PublicKey)
	return pubkey, nil
}

func verifyCertChain(certs []*x509.Certificate) error {
	for i, cert := range certs {
		if (i + 1) == len(certs) {
			err := verifyRoot(cert)
			if err != nil {
				return fmt.Errorf("Certificate %d %q is root but fails validation: %v",
					i, cert.Subject.CommonName, err)
			}
			log.Printf("Certificate %d %q is a valid root", i, cert.Subject.CommonName)
		} else {
			// check that cert is signed by parent
			err := cert.CheckSignatureFrom(certs[i+1])
			if err != nil {
				return fmt.Errorf("Certificate %d %q is not signed by parent certificate %d %q: %v",
					i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName, err)
			}
			log.Printf("Certificate %d %q has a valid signature from parent certificate %d %q",
				i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName)
		}
		if time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter) {
			// cert expires in less than 30 days, this is a soft error. send an email.
			err := sendSoftNotification(
				fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
				"Certificate %d %q expires in less than 30 days: notAfter=%s",
				i, cert.Subject.CommonName, cert.NotAfter)
			if err != nil {
				log.Printf("failed to send soft notification: %v", err)
			}
		}
		if time.Now().Add(15 * 24 * time.Hour).After(cert.NotAfter) {
			return fmt.Errorf("Certificate %d %q expires in less than 15 days: notAfter=%s",
				i, cert.Subject.CommonName, cert.NotAfter)
		}
		if time.Now().Before(cert.NotBefore) {
			return fmt.Errorf("Certificate %d %q is not yet valid: notBefore=%s",
				i, cert.Subject.CommonName, cert.NotBefore)
		}
		log.Printf("Certificate %d %q is valid from %s to %s",
			i, cert.Subject.CommonName, cert.NotBefore, cert.NotAfter)
	}
	return nil
}

func verifyRoot(cert *x509.Certificate) error {
	// this is the last cert, it should be self signed
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return fmt.Errorf("subject does not match issuer, should be equal")
	}
	if !cert.IsCA {
		return fmt.Errorf("missing IS CA extension")
	}
	if conf.RootHash != "" {
		rhash := strings.Replace(conf.RootHash, ":", "", -1)
		// We're configure to check the root hash matches expected value
		h := sha256.Sum256(cert.Raw)
		chash := fmt.Sprintf("%X", h[:])
		if rhash != chash {
			return fmt.Errorf("hash does not match expected root: expected=%s; got=%s", rhash, chash)
		}
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
