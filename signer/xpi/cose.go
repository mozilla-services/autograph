package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
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

// generateIssuerEEKeyPair returns a public and private key pair for
// the provided COSEAlgorithm
func (s *XPISigner) generateCOSEKeyPair(coseAlg *cose.Algorithm) (eeKey crypto.PrivateKey, eePublicKey crypto.PublicKey, err error) {
	var signer *cose.Signer

	switch coseAlg {
	case nil:
		err = fmt.Errorf("Cannot generate private key for nil cose Algorithm")
	case cose.PS256:
		const size = 2048
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate rsa private key of size %d", size)
			return
		}
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	case cose.ES256:
		fallthrough
	case cose.ES384:
		fallthrough
	case cose.ES512:
		signer, err = cose.NewSigner(coseAlg, nil)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate private key")
			return
		}
		eeKey = signer.PrivateKey
		eePublicKey = eeKey.(*ecdsa.PrivateKey).Public()
	}
	return
}

// isSupportedCOSEAlgValue returns whether the COSE alg value is supported or not
func isSupportedCOSEAlgValue(algValue interface{}) bool {
	return (algValue == cose.PS256.Value ||
		algValue == cose.ES256.Value ||
		algValue == cose.ES384.Value ||
		algValue == cose.ES512.Value)
}


func expectHeadersAndGetKeyID(actual, expected *cose.Headers) (kidValue interface{}, err error) {
	if actual == nil || expected == nil {
		err = errors.New("xpi: cannot compare nil COSE headers")
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
		if !isSupportedCOSEAlgValue(algValue) {
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

// isValidCOSESignature checks whether a COSE signature is valid for XPIs
func isValidCOSESignature(sig *cose.Signature) (eeCert *x509.Certificate, err error) {
	if sig == nil {
		err = errors.New("xpi: cannot validate nil COSE Signature")
		return
	}

	kidValue, err := expectHeadersAndGetKeyID(sig.Headers, expectedSignatureHeaders)
	if err != nil {
		err = errors.Wrapf(err, "xpi: got unexpected COSE Signature headers")
		return
	}

	kidBytes, ok := kidValue.([]byte)
	if !ok {
		err = fmt.Errorf("xpi: COSE Signature kid value is not a byte array")
		return
	}

	eeCert, err = x509.ParseCertificate(kidBytes)
	if err != nil {
		err = errors.Wrapf(err, "xpi: failed to parse X509 EE certificate from COSE Signature")
		return
	}

	return
}

// isValidCOSEMessage checks whether a COSE SignMessage is a valid for
// XPIs and returns parsed intermediate and end entity certs
func isValidCOSEMessage(msg *cose.SignMessage) (intermediateCerts, eeCerts []*x509.Certificate, err error) {
	if msg == nil {
		err = errors.New("xpi: cannot validate nil COSE SignMessage")
		return
	}
	if msg.Payload != nil {
		err = fmt.Errorf("xpi: expected SignMessage payload to be nil, but got %v", msg.Payload)
		return
	}
	kidValue, err := expectHeadersAndGetKeyID(msg.Headers, expectedMessageHeaders)
	if err != nil {
		err = errors.Wrapf(err, "xpi: got unexpected COSE SignMessage headers")
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
			err = errors.Wrapf(parseErr, "xpi: SignMessage Signature Protected Headers kid value %d does not decode to a parseable X509 cert", i)
			return
		}
		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	for i, sig := range msg.Signatures {
		eeCert, sigErr := isValidCOSESignature(&sig)
		if sigErr != nil {
			err = errors.Wrapf(sigErr, "xpi: cose signature %d is invalid", i)
			return
		}
		eeCerts = append(eeCerts, eeCert)
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
// TODO: 6) there is a trusted path from the included COSE EE certs to the signer cert using the provided intermediates
//
func verifyCOSESignatures(signedFile signer.SignedFile, truststore *x509.CertPool, signOptions Options) error {
	coseManifest, err := readFileFromZIP(signedFile, "META-INF/cose.manifest")
	if err != nil {
		return fmt.Errorf("xpi: failed to read META-INF/cose.manifest from signed zip: %v", err)
	}
	coseMsgBytes, err := readFileFromZIP(signedFile, "META-INF/cose.sig")
	if err != nil {
		return fmt.Errorf("xpi: failed to read META-INF/cose.sig from signed zip: %v", err)
	}
	pkcs7Manifest, err := readFileFromZIP(signedFile, "META-INF/manifest.mf")
	if err != nil {
		return fmt.Errorf("xpi: failed to read META-INF/manifest.mf from signed zip: %v", err)
	}

	var coseFileNames = [][]byte{
		[]byte("Name: META-INF/cose.sig"),
		[]byte("Name: META-INF/cose.manifest"),
	}
	for _, coseFileName := range coseFileNames {
		if !bytes.Contains(pkcs7Manifest, coseFileName) {
			return fmt.Errorf("xpi: pkcs7 manifest does not contain the line: %s", coseFileName)
		}

		if bytes.Contains(coseManifest, coseFileName) {
			return fmt.Errorf("xpi: cose manifest contains the line: %s", coseFileName)
		}
	}

	xpiSig, unmarshalErr := Unmarshal(base64.StdEncoding.EncodeToString(coseMsgBytes), nil)
	if unmarshalErr != nil {
		return errors.Wrap(unmarshalErr, "xpi: error unmarshaling cose.sig")
	}
	if xpiSig != nil && xpiSig.signMessage != nil && len(xpiSig.signMessage.Signatures) != len(signOptions.COSEAlgorithms) {
		return fmt.Errorf("xpi: cose.sig contains %d signatures, but expected %d", len(xpiSig.signMessage.Signatures), len(signOptions.COSEAlgorithms))
	}

	intermediateCerts, eeCerts, err := isValidCOSEMessage(xpiSig.signMessage)
	if err != nil {
		return errors.Wrap(err, "xpi: cose.sig is not a valid COSE SignMessage")
	}

	// check that we can verify EE certs with the provided intermediates
	intermediates := x509.NewCertPool()
	for _, intermediateCert := range intermediateCerts {
		intermediates.AddCert(intermediateCert)
	}
	cndigest := sha256.Sum256([]byte(signOptions.ID))
	dnsName := fmt.Sprintf("%x.%x.addons.mozilla.org", cndigest[:16], cndigest[16:])

	for i, eeCert := range eeCerts {
		opts := x509.VerifyOptions{
			DNSName:       dnsName,
			Roots:         truststore,
			Intermediates: intermediates,
		}
		if _, err := eeCert.Verify(opts); err != nil {
			return fmt.Errorf("failed to verify EECert %d %s", i, err)
		}
	}
	return nil
}

// issueCOSESignature returns a CBOR-marshalled COSE SignMessage
// after generating EE certs and signatures for the COSE algorithms
func (s *XPISigner) issueCOSESignature(cn string, manifest []byte, algs []*cose.Algorithm) (coseSig []byte, err error) {
	if s == nil {
		return nil, errors.New("Cannot issue COSE Signature from nil XPISigner")
	}
	if s.issuerCert == nil {
		return nil, errors.New("Cannot issue COSE Signature when XPISigner.issuerCert is nil")
	}

	var (
		coseSigners []cose.Signer
		tmp         = cose.NewSignMessage()
		msg         = &tmp
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
			return nil, errors.Wrap(err, "xpi: COSE signer creation failed")
		}
		coseSigners = append(coseSigners, *signer)

		// create a COSE Signature holder
		sig := cose.NewSignature()
		sig.Headers.Protected["alg"] = alg.Name
		sig.Headers.Protected["kid"] = eeCert.Raw[:]
		msg.AddSignature(sig)
	}

	// external_aad data must be nil and not byte("")
	err = msg.Sign(rand.Reader, nil, coseSigners)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: COSE signing failed")
	}
	// for addons the signature is detached and the payload is always nil / null
	msg.Payload = nil

	coseSig, err = cose.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: error serializing COSE signatures to CBOR")
	}

	return
}
