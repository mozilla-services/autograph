package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer/contentsignaturepki"
	csigverifier "github.com/mozilla-services/autograph/verifier/contentsignature"
)

// contentSignatureIgnoredLeafCertCNs maps EE/leaf certificate CNs to a bool
// for EE no longer in use but not yet removed from the autograph
// config that we don't want to alert on.
//
// https://bugzilla.mozilla.org/show_bug.cgi?id=1466523
//
var contentSignatureIgnoredLeafCertCNs = map[string]bool{
	// "fingerprinting-defenses.content-signature.mozilla.org": true,
	// "fennec-dlc.content-signature.mozilla.org":              true,
	// "focus-experiments.content-signature.mozilla.org":       true,
}

// CertNotification is a warning about a pending or resolved cert
// expiration
type CertNotification struct {
	// cert.Subject.CommonName
	CN string
	// "warning" or "info"
	Severity string
	// Message is the notification message
	Message string
}

// validate the signature and certificate chain of a content signature response
//
// If an X5U value was provided, use the public key from the end entity certificate
// to verify the sig. Otherwise, use the PublicKey contained in the response.
//
// If the signature passes, verify the chain of trust maps.
func verifyContentSignature(x5uClient *http.Client, notifier Notifier, rootHash string, ignoredCerts map[string]bool, response formats.SignatureResponse) (err error) {
	if response.X5U == "" {
		return fmt.Errorf("content signature response is missing an X5U to fetch")
	}
	var (
		certChain []byte
		certs     []*x509.Certificate
	)
	// GetX5U verifies chain contains three certs
	certChain, certs, err = contentsignaturepki.GetX5U(x5uClient, response.X5U)
	if err != nil {
		return fmt.Errorf("error fetching content signature signature x5u: %w", err)
	}
	err = csigverifier.Verify([]byte(inputdata), certChain, response.Signature, rootHash)
	if err != nil {
		// check if we should ignore this cert
		if _, ok := ignoredCerts[certs[0].Subject.CommonName]; ok {
			return nil
		}
		return err
	}
	notifications, err := verifyCertChain(rootHash, certs)
	if notifier != nil {
		for _, notification := range notifications {
			notifyErr := notifier.Send(notification.CN, notification.Severity, notification.Message)
			if notifyErr != nil {
				log.Printf("failed to send soft notification: %v", notifyErr)
			}
		}
	}
	return nil
}

// verifyCertChain checks certs in a chain slice (usually [EE, intermediate, root]) are:
//
// 1) signed by their parent/issuer/the next cert in the chain or if they're the last cert that they're self-signed and all func verifyRoot checks pass
// 2) valid for the current time i.e. cert NotBefore < current time < cert NotAfter
//
// It returns cert notifications for each cert expiring in less than
// 30 days and an error if any of the above checks fail or any cert in
// the chain expires in 15 days or less.
//
func verifyCertChain(rootHash string, certs []*x509.Certificate) (notifications []CertNotification, err error) {
	for i, cert := range certs {
		if (i + 1) == len(certs) {
			err = verifyRoot(rootHash, cert)
			if err != nil {
				err = fmt.Errorf("Certificate %d %q is root but fails validation: %v",
					i, cert.Subject.CommonName, err)
				return
			}
			log.Printf("Certificate %d %q is a valid root", i, cert.Subject.CommonName)
		} else {
			// check that cert is signed by parent
			checkCertErr := cert.CheckSignatureFrom(certs[i+1])
			if checkCertErr != nil {
				err = fmt.Errorf("Certificate %d %q is not signed by parent certificate %d %q: %v",
					i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName, checkCertErr)
				return
			}
			log.Printf("Certificate %d %q has a valid signature from parent certificate %d %q",
				i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName)
		}
		var (
			notificationSeverity, notificationMessage string
			err                                       error
			timeToExpiration                          = cert.NotAfter.Sub(time.Now())
			timeToValid                               = cert.NotBefore.Sub(time.Now())
		)
		if timeToExpiration < 30*24*time.Hour {
			notificationSeverity = "warning"
			// cert expires in less than 30 days, this is a soft error. send an email.
			notificationMessage = fmt.Sprintf("Certificate %d for %q expires in less than 30 days: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
			log.Printf(notificationMessage)
		}
		if timeToExpiration < 15*24*time.Hour {
			err = fmt.Errorf("Certificate %d %q expires in less than 15 days: notAfter=%s",
				i, cert.Subject.CommonName, cert.NotAfter)
		}
		if timeToExpiration < -time.Nanosecond {
			err = fmt.Errorf("Certificate %d %q expired: notAfter=%s",
				i, cert.Subject.CommonName, cert.NotAfter)
		}
		if timeToValid > time.Nanosecond {
			err = fmt.Errorf("Certificate %d %q is not yet valid: notBefore=%s",
				i, cert.Subject.CommonName, cert.NotBefore)
		}
		if err == nil {
			notificationSeverity = "info"
			notificationMessage = fmt.Sprintf(fmt.Sprintf("Certificate %d %q is valid from %s to %s",
				i, cert.Subject.CommonName, cert.NotBefore, cert.NotAfter))
			log.Printf(notificationMessage)
		}
		notifications = append(notifications, CertNotification{
			CN:       cert.Subject.CommonName,
			Severity: notificationSeverity,
			Message:  notificationMessage,
		})
		if err != nil {
			return notifications, err
		}
	}
	return notifications, nil
}

// verifyRoot checks that a root cert is:
//
// 1) self-signed
// 2) a CA
// 3) has the x509v3 Extentions for CodeSigning use
//
// and SHA2 sum of raw bytes matches the provided rootHash param
// (e.g. from openssl x509 -noout -text -fingerprint -sha256 -in ca.crt)
func verifyRoot(rootHash string, cert *x509.Certificate) error {
	// this is the last cert, it should be self signed
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return fmt.Errorf("subject does not match issuer, should be equal")
	}
	if !cert.IsCA {
		return fmt.Errorf("missing IS CA extension")
	}
	if rootHash != "" {
		rhash := strings.Replace(rootHash, ":", "", -1)
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
