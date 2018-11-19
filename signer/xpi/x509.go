package xpi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/cose"
)

// populateRsaCache adds rsa keys of a given size to the cache until
// the channel is full then it blocks
func (s *XPISigner) populateRsaCache(size int) {
	for {
		key, err := rsa.GenerateKey(s.rand, size)
		if err != nil {
			log.Fatalf("xpi.populateRsaCache: %v", err)
		}
		s.rsaCache <- key
	}
}

// retrieve a key from the cache or generate one if it takes too long
// or if the size is wrong
func (s *XPISigner) getRsaKey(size int) (*rsa.PrivateKey, error) {
	select {
	case key := <-s.rsaCache:
		if key.N.BitLen() != size {
			// it's theoritically impossible for this to happen
			// because the end entity has the same key size has
			// the signer, but we're paranoid so handling it
			log.Printf("WARNING: xpi rsa cache returned a key of size %d when %d was requested", key.N.BitLen(), size)
			return rsa.GenerateKey(rand.Reader, size)
		}
		return key, nil
	case <-time.After(100 * time.Millisecond):
		// generate a key if none available
		log.Printf("xpi: RSA key cache exhausted. Generating a new key")
		return rsa.GenerateKey(rand.Reader, size)
	}
}

// makeTemplate returns a pointer to a template for an x509.Certificate EE
func (s *XPISigner) makeTemplate(cn string) *x509.Certificate {
	cndigest := sha256.Sum256([]byte(cn))
	return &x509.Certificate{
		// The maximum length of a serial number per rfc 5280 is 20 bytes / 160 bits
		// https://tools.ietf.org/html/rfc5280#section-4.1.2.2
		// Setting it to nanoseconds guarantees we'll never have two conflicting serials
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		// PKIX requires EE's to have a valid DNS Names when the intermediate has
		// a constraint, so we hash the CN into an fqdn to get something unique enough
		DNSNames: []string{fmt.Sprintf("%x.%x.addons.mozilla.org", cndigest[:16], cndigest[16:])},
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Addons"},
			OrganizationalUnit: []string{s.OU},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"Mountain View"},
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(8760 * time.Hour), // one year
		SignatureAlgorithm: s.issuerCert.SignatureAlgorithm,
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}
}

// generateIssuerEEKeyPair returns a public and private key pair
// matching the issuer XPISigner issuerKey size and type
func (s *XPISigner) generateIssuerEEKeyPair() (eeKey crypto.PrivateKey, eePublicKey crypto.PublicKey, err error) {
	switch s.issuerKey.(type) {
	case *rsa.PrivateKey:
		size := s.issuerKey.(*rsa.PrivateKey).N.BitLen()
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate rsa private key of size %d", size)
			return
		}
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	case *ecdsa.PrivateKey:
		curve := s.issuerKey.(*ecdsa.PrivateKey).Curve
		eeKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate ecdsa private key on curve %s", curve.Params().Name)
			return
		}
		eePublicKey = eeKey.(*ecdsa.PrivateKey).Public()
	}
	return
}

// MakeEndEntity generates a private key and certificate ready to sign a given XPI.
//
// The subject CN of the certificate is taken from the `cn` string argument.
//
// The key type is identical to the key type of the signer that issues
// the certificate when the optional `coseAlg` argument is nil. For
// example, if the signer uses an RSA 2048 key, so will the
// end-entity. When `coseAlg` is not nil, a key type of the COSE
// algorithm is generated.
//
// The signature expiration date is copied over from the issuer.
//
// The signed x509 certificate and private key are returned.
func (s *XPISigner) MakeEndEntity(cn string, coseAlg *cose.Algorithm) (eeCert *x509.Certificate, eeKey crypto.PrivateKey, err error) {
	var (
		eePublicKey crypto.PublicKey
		derCert     []byte
	)

	template := s.makeTemplate(cn)

	if coseAlg == nil {
		eeKey, eePublicKey, err = s.generateIssuerEEKeyPair()
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: error generating key matching issuer")
			return
		}
	} else {
		eeKey, eePublicKey, err = s.generateCOSEKeyPair(coseAlg)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: error generating key matching COSE Algorithm type %s", coseAlg.Name)
			return
		}
	}

	derCert, err = x509.CreateCertificate(rand.Reader, template, s.issuerCert, eePublicKey, s.issuerKey)
	if err != nil {
		err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to create certificate")
		return
	}
	if len(derCert) == 0 {
		err = errors.Errorf("xpi.MakeEndEntity: certificate creation failed for an unknown reason")
		return
	}
	eeCert, err = x509.ParseCertificate(derCert)
	if err != nil {
		err = errors.Wrapf(err, "xpi.MakeEndEntity: certificate parsing failed")
	}
	return
}
