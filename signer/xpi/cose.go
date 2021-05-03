package xpi // import "github.com/mozilla-services/autograph/signer/xpi"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/mozilla-services/autograph/signer"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/cose"
)

const (
	// algHeaderValue compresses to 1 for the key "alg"
	algHeaderValue = 1
	// kidHeaderValue compresses to 4 for the key "kid"
	kidHeaderValue = 4
)

// stringToCOSEAlg returns the cose.Algorithm for a string or nil if
// the algorithm isn't implemented
func stringToCOSEAlg(s string) (v *cose.Algorithm) {
	switch strings.ToUpper(s) {
	case cose.PS256.Name:
		v = cose.PS256
	case cose.ES256.Name:
		v = cose.ES256
	case cose.ES384.Name:
		v = cose.ES384
	case cose.ES512.Name:
		v = cose.ES512
	default:
		v = nil
	}
	return v
}

// stringToCOSEAlg returns the cose.Algorithm for an int or nil if
// the algorithm isn't implemented
func intToCOSEAlg(i int) (v *cose.Algorithm) {
	switch i {
	case cose.PS256.Value:
		v = cose.PS256
	case cose.ES256.Value:
		v = cose.ES256
	case cose.ES384.Value:
		v = cose.ES384
	case cose.ES512.Value:
		v = cose.ES512
	default:
		v = nil
	}
	return v
}

// generateIssuerEEKeyPair returns a public and private key pair for
// the provided COSEAlgorithm
func (s *XPISigner) generateCOSEKeyPair(coseAlg *cose.Algorithm) (eeKey crypto.PrivateKey, eePublicKey crypto.PublicKey, err error) {
	var signer *cose.Signer

	switch key := s.issuerPublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		// ok
	default:
		err = fmt.Errorf("xpi: Cannot generate COSEKeypair for issuerKey type %T", key)
		return
	}

	switch coseAlg {
	case cose.PS256:
		var size = rsaKeyMinSize
		switch key := s.issuerPublicKey.(type) {
		case *rsa.PublicKey:
			pubKeySize, getKeySizeErr := s.getIssuerRSAKeySize()
			if err != nil { // should never occur since we just checked it's type *rsa.PublicKey
				err = fmt.Errorf("xpi: error determining issuerPublicKey rsa key size for key type %T: %w", key, getKeySizeErr)
				return
			}
			if pubKeySize > size {
				size = pubKeySize
			}
		default:
			log.Infof("xpi: using default RSA key size %d since issuer key type %T is not RSA", size, key)
		}
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = fmt.Errorf("xpi: failed to generate rsa private key of size %d: %w", size, err)
			return
		}
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	case cose.ES256, cose.ES384, cose.ES512:
		signer, err = cose.NewSigner(coseAlg, nil)
		if err != nil {
			err = fmt.Errorf("xpi: failed to generate private key: %w", err)
			return
		}
		eeKey = signer.PrivateKey
		eePublicKey = eeKey.(*ecdsa.PrivateKey).Public()
	case nil:
		err = fmt.Errorf("xpi: cannot generate private key for nil cose Algorithm")
	default:
		err = fmt.Errorf("xpi: cannot generate private key for unsupported cose Algorithm %q", coseAlg.Name)
	}
	return
}

func expectHeadersAndGetKeyIDAndAlg(actual, expected *cose.Headers) (kidValue interface{}, alg *cose.Algorithm, err error) {
	if actual == nil || expected == nil {
		err = fmt.Errorf("xpi: cannot compare nil COSE headers")
		return
	}
	if len(actual.Unprotected) != len(expected.Unprotected) {
		err = fmt.Errorf("xpi: unexpected non-empty Unprotected headers got: %v", actual.Unprotected)
		return
	}
	if len(actual.Protected) != len(expected.Protected) {
		err = fmt.Errorf("xpi: unexpected Protected headers got: %v expected: %v", actual.Protected, expected.Protected)
		return
	}
	if _, ok := expected.Protected[algHeaderValue]; ok {
		algValue, ok := actual.Protected[algHeaderValue]
		if !ok {
			err = fmt.Errorf("xpi: missing expected alg in Protected Headers")
			return
		}
		if algInt, ok := algValue.(int); ok {
			alg = intToCOSEAlg(algInt)
		}
		if alg == nil {
			err = fmt.Errorf("xpi: alg %v is not supported", algValue)
			return
		}
	}
	if _, ok := expected.Protected[kidHeaderValue]; ok {
		kidValue, ok = actual.Protected[kidHeaderValue]
		if !ok {
			err = fmt.Errorf("xpi: missing expected kid in Protected Headers")
			return
		}
	}
	return
}

var (
	expectedMessageHeaders = &cose.Headers{
		Unprotected: map[interface{}]interface{}{},
		Protected: map[interface{}]interface{}{
			kidHeaderValue: nil,
		},
	}
	expectedSignatureHeaders = &cose.Headers{
		Unprotected: map[interface{}]interface{}{},
		Protected: map[interface{}]interface{}{
			kidHeaderValue: nil,
			algHeaderValue: nil,
		},
	}
)

// validateCOSESignatureStructureAndGetEECert checks whether a COSE
// signature structure is valid for an XPI and returns the parsed EE
// Cert from the protected header key id value. It does not verify the
// COSE signature bytes
func validateCOSESignatureStructureAndGetEECertAndAlg(sig *cose.Signature) (eeCert *x509.Certificate, algValue *cose.Algorithm, err error) {
	if sig == nil {
		err = fmt.Errorf("xpi: cannot validate nil COSE Signature")
		return
	}

	kidValue, algValue, err := expectHeadersAndGetKeyIDAndAlg(sig.Headers, expectedSignatureHeaders)
	if err != nil {
		err = fmt.Errorf("xpi: got unexpected COSE Signature headers: %w", err)
		return
	}

	kidBytes, ok := kidValue.([]byte)
	if !ok {
		err = fmt.Errorf("xpi: COSE Signature kid value is not a byte array")
		return
	}

	eeCert, err = x509.ParseCertificate(kidBytes)
	if err != nil {
		err = fmt.Errorf("xpi: failed to parse X509 EE certificate from COSE Signature: %w", err)
		return
	}

	return
}

// validateCOSEMessageStructureAndGetCerts checks whether a COSE
// SignMessage structure is valid for an XPI and returns the parsed
// intermediate and EE Certs from the protected header key id
// values. It does not verify the COSE signature bytes
func validateCOSEMessageStructureAndGetCertsAndAlgs(msg *cose.SignMessage) (intermediateCerts, eeCerts []*x509.Certificate, algs []*cose.Algorithm, err error) {
	if msg == nil {
		err = fmt.Errorf("xpi: cannot validate nil COSE SignMessage")
		return
	}
	if msg.Payload != nil {
		err = fmt.Errorf("xpi: expected SignMessage payload to be nil, but got %v", msg.Payload)
		return
	}
	kidValue, _, err := expectHeadersAndGetKeyIDAndAlg(msg.Headers, expectedMessageHeaders)
	if err != nil {
		err = fmt.Errorf("xpi: got unexpected COSE SignMessage headers: %w", err)
		return
	}

	// check that all kid values are bytes and decode into certs
	kidArray, ok := kidValue.([]interface{})
	if !ok {
		err = fmt.Errorf("xpi: expected SignMessage Protected Headers kid value to be an array got %v with type %T", kidValue, kidValue)
		return
	}
	for i, cert := range kidArray {
		certBytes, ok := cert.([]byte)
		if !ok {
			err = fmt.Errorf("xpi: expected SignMessage Protected Headers kid value %d to be a byte slice got %v with type %T", i, cert, cert)
			return
		}
		intermediateCert, parseErr := x509.ParseCertificate(certBytes)
		if parseErr != nil {
			err = fmt.Errorf("xpi: SignMessage Signature Protected Headers kid value %d does not decode to a parseable X509 cert: %w", i, parseErr)
			return
		}
		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	for i, sig := range msg.Signatures {
		eeCert, alg, sigErr := validateCOSESignatureStructureAndGetEECertAndAlg(&sig)
		if sigErr != nil {
			err = fmt.Errorf("xpi: cose signature %d is invalid: %w", i, sigErr)
			return
		}
		eeCerts = append(eeCerts, eeCert)
		algs = append(algs, alg)
	}

	return
}

// verifyCOSESignatures checks that:
//
// 1) COSE manifest and signature files are present
// 2) the PKCS7 manifest is present
// 3) the COSE and PKCS7 manifests do not include COSE files
// 4) we can decode the COSE signature and it has the right format for an XPI
// 5) the right number of signatures are present and all intermediate and end entity certs parse properly
// 6) **when a non-nil truststore is provided** that there is a trusted path from the included COSE EE certs to the signer cert using the provided intermediates
// 7) use the public keys from the EE certs to verify the COSE signature bytes
//
func verifyCOSESignatures(signedFile signer.SignedFile, truststore *x509.CertPool, signOptions Options) error {
	coseManifest, err := readFileFromZIP(signedFile, coseManifestPath)
	if err != nil {
		return fmt.Errorf("xpi: failed to read META-INF/cose.manifest from signed zip: %w", err)
	}
	coseMsgBytes, err := readFileFromZIP(signedFile, coseSigPath)
	if err != nil {
		return fmt.Errorf("xpi: failed to read META-INF/cose.sig from signed zip: %w", err)
	}
	pkcs7Manifest, err := readFileFromZIP(signedFile, pkcs7ManifestPath)
	if err != nil {
		return fmt.Errorf("xpi: failed to read META-INF/manifest.mf from signed zip: %w", err)
	}

	var coseFilePaths = []string{
		coseSigPath,
		coseManifestPath,
	}
	for _, coseFilePath := range coseFilePaths {
		var coseFileEntry = []byte("Name: " + coseFilePath)
		if !bytes.Contains(pkcs7Manifest, coseFileEntry) {
			return fmt.Errorf("xpi: pkcs7 manifest does not contain the line: %q", coseFileEntry)
		}

		if bytes.Contains(coseManifest, coseFileEntry) {
			return fmt.Errorf("xpi: cose manifest contains the line: %q", coseFileEntry)
		}
	}

	xpiSig, unmarshalErr := Unmarshal(base64.StdEncoding.EncodeToString(coseMsgBytes), nil)
	if unmarshalErr != nil {
		return fmt.Errorf("xpi: error unmarshaling cose.sig: %w", unmarshalErr)
	}
	if xpiSig != nil && xpiSig.signMessage != nil && len(xpiSig.signMessage.Signatures) != len(signOptions.COSEAlgorithms) {
		return fmt.Errorf("xpi: cose.sig contains %d signatures, but expected %d", len(xpiSig.signMessage.Signatures), len(signOptions.COSEAlgorithms))
	}

	intermediateCerts, eeCerts, algs, err := validateCOSEMessageStructureAndGetCertsAndAlgs(xpiSig.signMessage)
	if err != nil {
		return fmt.Errorf("xpi: cose.sig is not a valid COSE SignMessage: %w", err)
	}

	// check that we can verify EE certs with the provided intermediates
	intermediates := x509.NewCertPool()
	for _, intermediateCert := range intermediateCerts {
		intermediates.AddCert(intermediateCert)
	}
	cndigest := sha256.Sum256([]byte(signOptions.ID))
	dnsName := fmt.Sprintf("%x.%x.addons.mozilla.org", cndigest[:16], cndigest[16:])

	var verifiers = []cose.Verifier{}

	for i, eeCert := range eeCerts {
		if signOptions.ID != eeCert.Subject.CommonName {
			return fmt.Errorf("xpi: EECert %d: id %q does not match cert cn %q", i, signOptions.ID, eeCert.Subject.CommonName)
		}
		opts := x509.VerifyOptions{
			DNSName:       dnsName,
			Roots:         truststore,
			Intermediates: intermediates,
			// EE cert must have the code signing ext key usage
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		if _, err := eeCert.Verify(opts); err != nil {
			return fmt.Errorf("xpi: failed to verify EECert %d: %w", i, err)
		}

		verifiers = append(verifiers, cose.Verifier{
			PublicKey: eeCert.PublicKey,
			Alg:       algs[i],
		})
	}

	xpiSig.signMessage.Payload = coseManifest
	err = xpiSig.signMessage.Verify(nil, verifiers)
	if err != nil {
		return fmt.Errorf("xpi: failed to verify COSE SignMessage Signatures: %w", err)
	}
	return nil
}

// issueCOSESignature returns a CBOR-marshalled COSE SignMessage
// after generating EE certs and signatures for the COSE algorithms
func (s *XPISigner) issueCOSESignature(cn string, manifest []byte, algs []*cose.Algorithm) (coseSig []byte, err error) {
	if s == nil {
		return nil, fmt.Errorf("xpi: cannot issue COSE Signature from nil XPISigner")
	}
	if s.issuerCert == nil {
		return nil, fmt.Errorf("xpi: cannot issue COSE Signature when XPISigner.issuerCert is nil")
	}
	if len(s.issuerCert.Raw) < 1100 {
		return nil, fmt.Errorf("xpi: cannot issue COSE Signature DER encoded XPISigner.issuerCert should be at least 1100 bytes long")
	}

	var (
		coseSigners []cose.Signer
		msg         = cose.NewSignMessage()
	)
	msg.Payload = manifest

	// Add list of DER encoded intermediate certificates as message key id
	msg.Headers.Protected["kid"] = [][]byte{s.issuerCert.Raw[:]}

	for _, alg := range algs {
		// create a cert and key
		eeCert, eeKey, err := s.MakeEndEntity(cn, alg)
		if err != nil {
			return nil, err
		}

		// create a COSE.Signer
		signer, err := cose.NewSignerFromKey(alg, eeKey)
		if err != nil {
			return nil, fmt.Errorf("xpi: COSE signer creation failed: %w", err)
		}
		coseSigners = append(coseSigners, *signer)

		// create a COSE Signature holder
		sig := cose.NewSignature()
		sig.Headers.Protected["alg"] = alg.Name
		sig.Headers.Protected["kid"] = eeCert.Raw[:]
		msg.AddSignature(sig)
	}

	// external_aad data must be nil and not byte("")
	err = msg.Sign(s.rand, nil, coseSigners)
	if err != nil {
		return nil, fmt.Errorf("xpi: COSE signing failed: %w", err)
	}
	// for addons the signature is detached and the payload is always nil / null
	msg.Payload = nil

	coseSig, err = cose.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("xpi: error serializing COSE signatures to CBOR: %w", err)
	}

	return
}
