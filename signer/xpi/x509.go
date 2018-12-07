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
	"math/big"
	"sync"
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
		key, err = rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			log.Fatalf("xpi: error generating RSA key for cache: %s", err)
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

type rsaKey struct {
	lock      sync.Mutex
	createdAt time.Time
	usage     int
	key       *rsa.PrivateKey
}

// getRsaKey applies some intelligence to key management. It will return the
// current key if its lifetime or usage count aren't exceeded, or will get a
// new key from the cache. If the cache is unresponsive, it will generate a new
// RSA key by itself and return it. All while publishing stats so we can
// monitor the state of the cache.
func (s *XPISigner) getRsaKey(size int) (*rsa.PrivateKey, error) {
	var (
		err   error
		start time.Time
	)

	// we're messing with pointers and counters shared across goroutines, so
	// only allow one execution of this function at a time
	s.currentRsaKey.lock.Lock()
	defer s.currentRsaKey.lock.Unlock()

	// see if we can reuse the current key
	if s.currentRsaKey.key != nil &&
		s.currentRsaKey.createdAt.Add(s.rsaKeyMaxAge).After(time.Now()) && // if current key hasn't reached max lifetime
		s.currentRsaKey.usage < s.rsaKeyMaxUsage { // if current key hasn't reached max usage
		s.currentRsaKey.usage++
		return s.currentRsaKey.key, nil
	}

	// we're making a new key, allocate a new pointer
	// to avoid messing with the old one
	start = time.Now()
	s.currentRsaKey.key = new(rsa.PrivateKey)
	s.currentRsaKey.createdAt = time.Now()
	s.currentRsaKey.usage = 1
	select {
	case s.currentRsaKey.key = <-s.rsaCache:
		if s.currentRsaKey.key.N.BitLen() != size {
			// it's theoritically impossible for this to happen
			// because the end entity has the same key size has
			// the signer, but we're paranoid so handling it
			log.Warnf("WARNING: xpi rsa cache returned a key of size %d when %d was requested", s.currentRsaKey.key.N.BitLen(), size)
			s.currentRsaKey.key, err = rsa.GenerateKey(rand.Reader, size)
		}
	case <-time.After(s.rsaCacheFetchTimeout):
		// generate a key if none available
		s.currentRsaKey.key, err = rsa.GenerateKey(rand.Reader, size)
	}

	if s.stats != nil {
		s.stats.SendHistogram("xpi.rsa_cache.get_key", time.Since(start))
	}
	return s.currentRsaKey.key, err
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
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
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
			err = errors.Wrapf(err, "xpi: failed to generate rsa private key of size %d", size)
			return
		}
		if eeKey == nil {
			err = errors.Wrapf(err, "xpi: failed to get rsa private key of size %d", size)
			return
		}

		newKey, ok := eeKey.(*rsa.PrivateKey)
		if !ok {
			err = errors.Wrapf(err, "xpi: failed to cast generated key of size %d to *rsa.PrivateKey", size)
			return
		}
		eePublicKey = newKey.Public()
	case *ecdsa.PrivateKey:
		curve := s.issuerKey.(*ecdsa.PrivateKey).Curve
		eeKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "xpi: failed to generate ecdsa private key on curve %s", curve.Params().Name)
			return
		}
		newKey, ok := eeKey.(*ecdsa.PrivateKey)
		if !ok {
			err = errors.Wrapf(err, "xpi: failed to cast generated key on curve %s to *ecdsa.PrivateKey", curve)
			return
		}
		eePublicKey = newKey.Public()
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
