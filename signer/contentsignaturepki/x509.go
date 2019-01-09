package contentsignaturepki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

// makeChain issues an end-entity certificate using the ca private key and the first
// cert of the chain (which is supposed to match the ca private key).  it
// returns the entire chain of certificate, its name (based on the ee cn &
// expiration) and an error.
func (s *ContentSigner) makeChain() (chain string, name string, err error) {
	cn := s.ID + CSNameSpace

	// cert is backdated to allow clock skew tolerance
	notBefore := time.Now().UTC().Add(-s.clockSkewTolerance)

	// cert will be in used for `validity` number of days, but will remain
	// valid for longer than that to account for clock skew
	notAfter := time.Now().UTC().Add(s.validity + s.clockSkewTolerance)

	// the issuer is the first cert in the chain
	block, _ := pem.Decode([]byte(s.PublicKey))
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = errors.Wrap(err, "failed to parse issuer certificate from chain")
		return
	}

	crtTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"Mountain View"},
		},
		DNSNames:           []string{cn},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: issuer.SignatureAlgorithm,
		IsCA:               false,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, crtTpl, issuer, s.eePub, s.issuerPriv)
	if err != nil {
		err = errors.Wrap(err, "failed to issue end-entity cert")
		return
	}

	var certPem bytes.Buffer
	err = pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		err = errors.Wrap(err, "failed to PEM encode end-entity cert")
		return
	}

	// verify the chain by making 2 cert pools, one for the root ca
	// and one for the intermediate, then verifying the cert chain
	root := x509.NewCertPool()
	ok := root.AppendCertsFromPEM([]byte(s.caCert))
	if !ok {
		err = errors.New("failed to load root cert")
		return
	}
	inter := x509.NewCertPool()
	inter.AddCert(issuer)
	opts := x509.VerifyOptions{
		Roots:         root,
		Intermediates: inter,
		KeyUsages:     crtTpl.ExtKeyUsage,
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		err = errors.Wrap(err, "failed to parse end-entity certificate")
		return
	}
	_, err = cert.Verify(opts)
	if err != nil {
		err = errors.Wrap(err, "failed to verify certificate")
		return
	}

	// return a chain with the EE cert first then the issuers
	chain = certPem.String() + s.PublicKey + s.caCert
	name = fmt.Sprintf("%s-%s.chain", cert.Subject.CommonName, cert.NotAfter.Format("20060102"))
	return
}
