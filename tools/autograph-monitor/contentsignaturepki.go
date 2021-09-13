package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
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

// day is one 24 hours period (approx is close enough to a calendar
// day for our purposes)
const day = 24 * time.Hour

// week is 7 24h days (close enough to a calendar week for our
// purposes)
const week = 7 * day

// month is 28 24h days (close enough to a calendar month for our
// purposes)
const month = 4 * week

// verifyContentSignature validates the signature and certificate
// chain of a content signature response.
//
// It fetches the X5U, sends soft notifications, verifies the content
// signature data and certificate chain trust to the provided root
// certificate SHA2 hash/fingerprint, and errors for pending
// expirations.
//
// Chains with leaf/EE CommonNames in ignoredCerts are ignored.
//
func verifyContentSignature(x5uClient *http.Client, notifier Notifier, rootHash string, ignoredCerts map[string]bool, response formats.SignatureResponse, input []byte) (err error) {
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
	if notifier != nil {
		notifications := certChainValidityNotifications(certs)
		// check if we should ignore this cert
		for i, notification := range notifications {
			if i == 0 {
				if _, ok := ignoredCerts[notification.CN]; ok {
					log.Printf("ignoring notifications for chain EE CN: %q", notification.CN)
					break
				}
			}
			err = notifier.Send(notification.CN, notification.Severity, notification.Message)
			if err != nil {
				log.Printf("failed to send soft notification: %v", err)
			}
		}
	}
	// errors if an cert is expired or not yet valid, verifies data and trust map to root hash
	err = csigverifier.Verify(input, certChain, response.Signature, rootHash)
	if err != nil {
		// check if we should ignore this cert
		if _, ok := ignoredCerts[certs[0].Subject.CommonName]; ok {
			log.Printf("ignoring chain EE CN %q verify error: %q", certs[0].Subject.CommonName, err)
			return nil
		}
		return err
	}
	// errors for pending expirations
	err = certChainPendingExpiration(certs)
	if err != nil {
		// check if we should ignore this cert
		if _, ok := ignoredCerts[certs[0].Subject.CommonName]; ok {
			log.Printf("ignoring chain EE CN %q pending expiration error: %q", certs[0].Subject.CommonName, err)
			return nil
		}
		return err
	}
	return nil
}

// certChainValidityNotifications checks the validity of a slice of
// x509 certificates and returns notifications whether the cert is
// valid, not yet valid, expired, or soon to expire
func certChainValidityNotifications(certs []*x509.Certificate) (notifications []*CertNotification) {
	for i, cert := range certs {
		var (
			severity, message string
			timeToExpiration  = cert.NotAfter.Sub(time.Now())
			timeToValid       = cert.NotBefore.Sub(time.Now())
		)
		switch {
		case timeToValid > time.Nanosecond:
			severity = "warning"
			message = fmt.Sprintf("Certificate %d %q is not yet valid: notBefore=%s", i, cert.Subject.CommonName, cert.NotBefore)
		case timeToExpiration < -time.Nanosecond:
			severity = "warning"
			message = fmt.Sprintf("Certificate %d %q expired: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
		case timeToExpiration < 15*day:
			severity = "warning"
			message = fmt.Sprintf("Certificate %d %q expires in less than 15 days: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
		case timeToExpiration < 30*day:
			severity = "warning"
			message = fmt.Sprintf("Certificate %d for %q expires in less than 30 days: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
		default:
			severity = "info"
			message = fmt.Sprintf("Certificate %d %q is valid from %s to %s", i, cert.Subject.CommonName, cert.NotBefore, cert.NotAfter)
		}
		log.Println(message)
		notifications = append(notifications, &CertNotification{
			CN:       cert.Subject.CommonName,
			Severity: severity,
			Message:  message,
		})
	}
	return notifications
}

// certChainPendingExpiration returns an error for the first pending
// expiration in 3-cert chain. It errors earlier for intermediate and
// root certs, since they're usually issued with a longer validity
// period and require more work to rotate.
//
func certChainPendingExpiration(certs []*x509.Certificate) error {
	for i, cert := range certs {
		timeToExpiration := cert.NotAfter.Sub(time.Now())

		switch i {
		case 0:
			if timeToExpiration < 15*day {
				return fmt.Errorf("leaf/EE certificate %d %q expires in less than 15 days: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
			}
		case 1:
			if timeToExpiration < 15*week { // almost 4 months
				return fmt.Errorf("intermediate certificate %d %q expires in less than 15 weeks: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
			}
		case 2:
			if timeToExpiration < 15*month { // ~5 quarters
				return fmt.Errorf("root certificate %d %q expires in less than 15 months: notAfter=%s", i, cert.Subject.CommonName, cert.NotAfter)
			}
		default:
			return fmt.Errorf("unexpected cert with index %d in chain ", i)
		}
	}
	return nil
}
