package contentsignaturepki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/mozilla-services/autograph/database"
	"github.com/mozilla-services/autograph/signer"
)

// findAndSetEE searches the database for an end-entity key that is currently
// valid for this signer and is not older than cfg.Validity days
func (s *ContentSigner) findAndSetEE(conf signer.Configuration) (err error) {
	var tmpX5U string
	if s.db == nil {
		// no database, no chance to find an existing key
		return database.ErrNoSuitableEEFound
	}
	// search the database for the label of an end-entity private key that is still valid.
	s.eeLabel, tmpX5U, err = s.db.GetLabelOfLatestEE(s.ID, s.validity)
	if err != nil {
		return
	}
	if tmpX5U != "" {
		s.X5U = tmpX5U
	}
	conf.PrivateKey = s.eeLabel
	s.rand = conf.GetRand()
	s.eePriv, s.eePub, s.PublicKey, err = conf.GetKeys()
	if err != nil {
		err = fmt.Errorf("found suitable end-entity labeled %q in database but not in hsm: %w", s.eeLabel, err)
		return
	}
	return
}

// makeAndUploadChain makes a certificate using the end-entity public key,
// uploads the chain to its destination and creates an X5U download URL
func (s *ContentSigner) makeAndUploadChain() (err error) {
	var fullChain, chainName string
	fullChain, chainName, err = s.makeChain()
	if err != nil {
		return fmt.Errorf("failed to make chain: %w", err)
	}
	err = s.upload(fullChain, chainName)
	if err != nil {
		return fmt.Errorf("failed to upload chain: %w", err)
	}
	newX5U := s.X5U + chainName
	_, _, err = GetX5U(buildHTTPClient(), newX5U)
	if err != nil {
		return fmt.Errorf("failed to download new chain: %w", err)
	}
	s.X5U = newX5U
	return
}

// makeChain issues an end-entity certificate using the ca private key and the first
// cert of the chain (which is supposed to match the ca private key).  it
// returns the entire chain of certificate, its name (based on the ee cn &
// expiration) and an error.
func (s *ContentSigner) makeChain() (chain string, name string, err error) {
	cn := s.domainForLeafCert()

	// cert is backdated to allow for clock skew tolerance
	notBefore := time.Now().UTC().Add(-s.clockSkewTolerance)

	// cert will be in used for `validity` number of days, but will remain
	// valid for longer than that to account for clock skew
	notAfter := time.Now().UTC().Add(s.validity + s.clockSkewTolerance)

	block, _ := pem.Decode([]byte(s.IssuerCert))
	if block == nil || block.Type != "CERTIFICATE" {
		err = fmt.Errorf("no pem block found in signer public key configuration")
		return
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse issuer certificate from chain: %w", err)
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
		DNSNames:    []string{cn},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(s.rand, crtTpl, issuer, s.eePub, s.issuerPriv)
	if err != nil {
		err = fmt.Errorf("failed to issue end-entity cert: %w", err)
		return
	}

	var certPem bytes.Buffer
	err = pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		err = fmt.Errorf("failed to PEM encode end-entity cert: %w", err)
		return
	}

	// verify the chain by making 2 cert pools, one for the root ca
	// and one for the intermediate, then verifying the cert chain
	root := x509.NewCertPool()
	ok := root.AppendCertsFromPEM([]byte(s.caCert))
	if !ok {
		err = fmt.Errorf("failed to load root cert")
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
		err = fmt.Errorf("failed to parse end-entity certificate: %w", err)
		return
	}
	_, err = cert.Verify(opts)
	if err != nil {
		err = fmt.Errorf("failed to verify certificate: %w", err)
		return
	}

	// return a chain with the EE cert first then the issuers
	chain = certPem.String() + s.IssuerCert + s.caCert
	name = fmt.Sprintf("%s-%s.chain", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02-15-04-05"))
	return
}

func (s *ContentSigner) domainForLeafCert() string {
	subdomain := s.ID
	if s.subdomainOverride != "" {
		subdomain = s.subdomainOverride
	}
	return subdomain + CSNameSpace
}
