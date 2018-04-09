package xpi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

// every minute, add an rsa key to the cache. This will block if
// the cache channel is already full, which is what we want anyway
func (s *PKCS7Signer) populateRsaCache(size int) {
	for {
		key, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			log.Fatalf("xpi.populateRsaCache: %v", err)
		}
		s.rsaCache <- key
		time.Sleep(time.Minute)
	}
}

// retrieve a key from the cache or generate one if it takes too long
// or if the size is wrong
func (s *PKCS7Signer) getRsaKey(size int) (*rsa.PrivateKey, error) {
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
		return rsa.GenerateKey(rand.Reader, size)
	}
}

// MakeEndEntity generates a private key and certificate ready to sign a given XPI.
// The subject CN of the certificate is taken from the `cn` string passed as argument.
// The type of key is identical to the key of the signer that issues the certificate,
// if the signer uses an RSA 2048 key, so will the end-entity. The signature algorithm
// and expiration date are also copied over from the issuer.
//
// The signed certificate and private key are returned.
func (s *PKCS7Signer) MakeEndEntity(cn string) (eeCert *x509.Certificate, eeKey crypto.PrivateKey, err error) {
	var derCert []byte
	template := x509.Certificate{
		// The maximum length of a serial number per rfc 5280 is 20 bytes / 160 bits
		// https://tools.ietf.org/html/rfc5280#section-4.1.2.2
		// Setting it to nanoseconds guarantees we'll never have two conflicting serials
		SerialNumber: big.NewInt(time.Now().UnixNano()),
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
	}
	switch s.issuerKey.(type) {
	case *rsa.PrivateKey:
		size := s.issuerKey.(*rsa.PrivateKey).N.BitLen()
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to generate rsa private key of size %d", size)
			return
		}
		derCert, err = x509.CreateCertificate(rand.Reader, &template, s.issuerCert, eeKey.(*rsa.PrivateKey).Public(), s.issuerKey.(*rsa.PrivateKey))
	case *ecdsa.PrivateKey:
		curve := s.issuerKey.(*ecdsa.PrivateKey).Curve
		eeKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "xpi.MakeEndEntity: failed to generate ecdsa private key on curve %s", curve.Params().Name)
			return
		}
		derCert, err = x509.CreateCertificate(rand.Reader, &template, s.issuerCert, eeKey.(*ecdsa.PrivateKey).Public(), s.issuerKey.(*ecdsa.PrivateKey))
	}
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
