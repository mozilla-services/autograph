package xpi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/cose"
)

// populateRsaCache adds an rsa key to the cache every
// XPISigner.rsaCacheSleepDuration, blocks when the cache channel is
// full, and should be run as a goroutine
func (s *XPISigner) populateRsaCache(size int) {
	var (
		err   error
		key   *rsa.PrivateKey
		start time.Time
	)
	for {
		start = time.Now()
		key, err = rsa.GenerateKey(s.rand, size)
		if err != nil {
			log.Fatalf("xpi: error generating RSA key for cache: %q", err)
		}
		if key == nil {
			log.Fatal("xpi: error generated nil RSA key for cache")
		}

		if s.stats != nil {
			s.stats.SendHistogram("xpi.rsa_cache.gen_key_dur", time.Since(start))
		}
		s.rsaCache <- key
		time.Sleep(s.rsaCacheGeneratorSleepDuration)
	}
}

// monitorRsaCacheSize sends the number of cached keys and cache size
// to datadog. It should be run as a goroutine
func (s *XPISigner) monitorRsaCacheSize() {
	if s.stats == nil {
		return
	}
	for {
		s.stats.SendGauge("xpi.rsa_cache.chan_len", len(s.rsaCache))

		// chan capacity should be constant but is useful for
		// knowing % cache filled across deploys
		s.stats.SendGauge("xpi.rsa_cache.chan_cap", cap(s.rsaCache))

		time.Sleep(s.rsaCacheSizeSampleRate)
	}
}

// retrieve a key from the cache or generate one if it takes too long
// or if the size is wrong
func (s *XPISigner) getRsaKey(size int) (*rsa.PrivateKey, error) {
	var (
		err   error
		key   *rsa.PrivateKey
		start time.Time
	)
	start = time.Now()
	select {
	case key = <-s.rsaCache:
		if key.N.BitLen() != size {
			// it's theoritically impossible for this to happen
			// because the end entity has the same key size has
			// the signer, but we're paranoid so handling it
			log.Warnf("WARNING: xpi rsa cache returned a key of size %d when %d was requested", key.N.BitLen(), size)
			key, err = rsa.GenerateKey(s.rand, size)
		}
	case <-time.After(s.rsaCacheFetchTimeout):
		// generate a key if none available
		key, err = rsa.GenerateKey(s.rand, size)
	}

	if s.stats != nil {
		s.stats.SendHistogram("xpi.rsa_cache.get_key", time.Since(start))
	}
	return key, err
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
		NotAfter:           time.Now().Add(87600 * time.Hour), // ten year
		SignatureAlgorithm: s.issuerCert.SignatureAlgorithm,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
}

// getIssuerRSAKeySize returns the rsa key size in bits for the issuer public key
func (s *XPISigner) getIssuerRSAKeySize() (size int, err error) {
	rsaKey, ok := s.issuerPublicKey.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("xpi: failed to cast public key to *rsa.PublicKey to get rsa key size")
		return
	}
	return rsaKey.N.BitLen(), nil
}

// getIssuerECDSACurve returns the ecdsa curve for the issuer public key
func (s *XPISigner) getIssuerECDSACurve() (curve elliptic.Curve, err error) {
	ecKey, ok := s.issuerPublicKey.(*ecdsa.PublicKey)
	if !ok {
		err = fmt.Errorf("xpi: failed to cast public key to *ecdsa.PublicKey to get curve")
		return
	}
	return ecKey.Curve, nil
}

// generateIssuerEEKeyPair returns a public and private key pair
// matching the issuer XPISigner issuerKey size and type
func (s *XPISigner) generateIssuerEEKeyPair() (eeKey crypto.PrivateKey, eePublicKey crypto.PublicKey, err error) {
	switch issuerKey := s.issuerPublicKey.(type) {
	case *rsa.PublicKey:
		var size int
		size, err = s.getIssuerRSAKeySize()
		if err != nil {
			err = fmt.Errorf("xpi: failed to get rsa key size: %w", err)
			return
		}
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = fmt.Errorf("xpi: failed to generate rsa private key of size %d: %w", size, err)
			return
		}
		if eeKey == nil {
			err = fmt.Errorf("xpi: failed to get rsa private key of size %d: %w", size, err)
			return
		}

		newKey, ok := eeKey.(*rsa.PrivateKey)
		if !ok {
			err = fmt.Errorf("xpi: failed to cast generated key of size %d to *rsa.PrivateKey: %w", size, err)
			return
		}
		eePublicKey = newKey.Public()
	case *ecdsa.PublicKey:
		var curve elliptic.Curve
		curve, err = s.getIssuerECDSACurve()
		if err != nil {
			err = fmt.Errorf("xpi: failed to get ecdsa curve: %w", err)
			return
		}
		eeKey, err = ecdsa.GenerateKey(curve, s.rand)
		if err != nil {
			err = fmt.Errorf("xpi: failed to generate ecdsa private key on curve %q: %w", curve.Params().Name, err)
			return
		}

		newKey, ok := eeKey.(*ecdsa.PrivateKey)
		if !ok {
			err = fmt.Errorf("xpi: failed to cast generated key on curve %q to *ecdsa.PrivateKey: %w", curve.Params().Name, err)
			return
		}
		eePublicKey = newKey.Public()
	default:
		err = fmt.Errorf("xpi: unrecognized issuer key type for EE: %T", issuerKey)
		return
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
			err = fmt.Errorf("xpi.MakeEndEntity: error generating key matching issuer: %w", err)
			return
		}
	} else {
		eeKey, eePublicKey, err = s.generateCOSEKeyPair(coseAlg)
		if err != nil {
			err = fmt.Errorf("xpi.MakeEndEntity: error generating key matching COSE Algorithm type %q: %w", coseAlg.Name, err)
			return
		}
	}

	derCert, err = x509.CreateCertificate(s.rand, template, s.issuerCert, eePublicKey, s.issuerKey)
	if err != nil {
		err = fmt.Errorf("xpi.MakeEndEntity: failed to create certificate: %w", err)
		return
	}
	if len(derCert) == 0 {
		err = fmt.Errorf("xpi.MakeEndEntity: certificate creation failed for an unknown reason")
		return
	}
	eeCert, err = x509.ParseCertificate(derCert)
	if err != nil {
		err = fmt.Errorf("xpi.MakeEndEntity: certificate parsing failed: %w", err)
	}
	return
}
