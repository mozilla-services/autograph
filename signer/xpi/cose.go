package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/cose"
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
func (s *PKCS7Signer) generateCOSEKeyPair(coseAlg *cose.Algorithm) (eeKey crypto.PrivateKey, eePublicKey crypto.PublicKey, err error) {
	var signer *cose.Signer

	if coseAlg == nil {
		err = fmt.Errorf("Cannot generate private key for nil cose Algorithm")
		return
	} else if coseAlg == cose.PS256 {
		const size = 2048
		eeKey, err = s.getRsaKey(size)
		if err != nil {
			err = errors.Wrapf(err, "failed to generate rsa private key of size %d", size)
			return
		}
		eePublicKey = eeKey.(*rsa.PrivateKey).Public()
	} else {
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
	return algValue == cose.PS256.Value || algValue == cose.ES256.Value || algValue == cose.ES384.Value || algValue == cose.ES512.Value
}

// isValidCOSESignature checks whether a COSE signature is a valid for XPIs
func isValidCOSESignature(sig cose.Signature) (eeCert *x509.Certificate, resultErr error) {
	if len(sig.Headers.Unprotected) != 0 {
		resultErr = fmt.Errorf("XPI COSE Signature must have an empty Unprotected Header")
		return
	}

	if len(sig.Headers.Protected) != 2 {
		resultErr = fmt.Errorf("XPI COSE Signature must have exactly two Protected Headers")
		return
	}
	algValue, ok := sig.Headers.Protected[1] // 1 is the compressed key for "alg"
	if !ok {
		resultErr = fmt.Errorf("XPI COSE Signature must have alg in Protected Headers")
		return
	}
	if !isSupportedCOSEAlgValue(algValue) {
		resultErr = fmt.Errorf("XPI COSE Signature must have alg %+v is not supported", algValue)
		return
	}

	kidValue, ok := sig.Headers.Protected[4] // 4 is the compressed key for "kid"
	if !ok {
		resultErr = fmt.Errorf("XPI COSE Signature must have kid in Protected Headers")
		return
	}
	kidBytes, ok := kidValue.([]byte)
	if !ok {
		resultErr = fmt.Errorf("XPI COSE Signature kid value is not bytes")
		return
	}

	eeCert, err := x509.ParseCertificate(kidBytes) // eeCert
	if err != nil {
		resultErr = errors.Wrapf(err, "XPI COSE Signature kid must decode to a parseable X509 cert")
		return
	}
	return
}

// isValidCOSEMessage checks whether a COSE SignMessage is a valid for
// XPIs and returns parsed intermediate and end entity certs
func isValidCOSEMessage(msg cose.SignMessage) (intermediateCerts, eeCerts []*x509.Certificate, resultErr error) {
	if msg.Payload != nil {
		resultErr = fmt.Errorf("Expected SignMessage payload to be nil, but got %+v", msg.Payload)
		return
	}
	if len(msg.Headers.Unprotected) != 0 {
		resultErr = fmt.Errorf("Expected SignMessage Unprotected headers to be empty, but got %+v", msg.Headers.Unprotected)
		return
	}

	if len(msg.Headers.Protected) != 1 {
		resultErr = fmt.Errorf("Expected SignMessage Protected headers must contain one value, but got %d", len(msg.Headers.Protected))
		return
	}
	kidValue, ok := msg.Headers.Protected[4] // 4 is the compressed key for "kid"
	if !ok {
		resultErr = fmt.Errorf("Expected SignMessage must have kid in Protected Headers")
		return
	}
	// check that all kid values are bytes and decode into certs
	kidArray, ok := kidValue.([]interface{})
	if !ok {
		resultErr = fmt.Errorf("Expected SignMessage Protected Headers kid value to be an array got %+v with type %T", kidValue, kidValue)
		return
	}
	for i, cert := range kidArray {
		certBytes, ok := cert.([]byte)
		if !ok {
			resultErr = fmt.Errorf("Expected SignMessage Protected Headers kid value %d to be a byte slice got %+v with type %T", i, cert, cert)
			return
		}
		intermediateCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			resultErr = errors.Wrapf(err, "SignMessage Signature Protected Headers kid value %d does not decode to a parseable X509 cert", i)
			return
		}
		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	for i, sig := range msg.Signatures {
		eeCert, err := isValidCOSESignature(sig)
		if err != nil {
			resultErr = errors.Wrapf(err, "cose signature %d is invalid", i)
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
func verifyCOSESignatures(signedFile signer.SignedFile, signOptions Options) error {
	coseManifestBytes, err := readFileFromZIP(signedFile, "META-INF/cose.manifest")
	if err != nil {
		return fmt.Errorf("failed to read META-INF/cose.manifest from signed zip: %v", err)
	}
	coseMsgBytes, err := readFileFromZIP(signedFile, "META-INF/cose.sig")
	if err != nil {
		return fmt.Errorf("failed to read META-INF/cose.sig from signed zip: %v", err)
	}
	pkcs7ManifestBytes, err := readFileFromZIP(signedFile, "META-INF/manifest.mf")
	if err != nil {
		return fmt.Errorf("failed to read META-INF/manifest.mf from signed zip: %v", err)
	}
	coseManifest := string(coseManifestBytes)
	pkcs7Manifest := string(pkcs7ManifestBytes)

	if !strings.Contains(pkcs7Manifest, "cose") {
		return fmt.Errorf("pkcs7 manifest does not contain cose files: %s", pkcs7Manifest)
	}
	if strings.Contains(coseManifest, "cose") {
		return fmt.Errorf("cose manifest contains cose files: %s", coseManifest)
	}

	coseObj, err := cose.Unmarshal(coseMsgBytes)
	if err != nil {
		return errors.Wrap(err, "error unmarshaling cose.sig")
	}
	coseMsg, ok := coseObj.(cose.SignMessage)
	if !ok {
		return fmt.Errorf("cose.sig not a SignMessage")
	}

	if len(coseMsg.Signatures) != len(signOptions.COSEAlgorithms) {
		return fmt.Errorf("cose.sig contains %d signatures, but expected %d", len(coseMsg.Signatures), len(signOptions.COSEAlgorithms))
	}

	// intermediateCerts, eeCerts, err := isValidCOSEMessage(coseMsg)
	_, _, err = isValidCOSEMessage(coseMsg)
	if err != nil {
		return errors.Wrap(err, "cose.sig is not a valid COSE SignMessage")
	}

	// check that we can verify EE certs with the provided intermediates
	// roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	// ok = roots.AppendCertsFromPEM([]byte(testcase.Certificate))
	// if !ok {
	// 	return fmt.Errorf("failed to add root cert to pool")
	// }
	// for _, intermediateCert := range intermediateCerts {
	// 	intermediates.AddCert(intermediateCert)
	// }
	// for i, eeCert := range eeCerts {
	// 	opts := x509.VerifyOptions{
	// 		DNSName:       signOptions.ID,
	// 		Roots:         roots,
	// 		Intermediates: intermediates,
	// 	}
	// 	if _, err := eeCert.Verify(opts); err != nil {
	// 		return fmt.Errorf("failed to verify EECert %d %s", i, err)
	// 	}
	// }
	return nil
}

// coseSignature returns a CBOR-marshalled COSE SignMessage
// after generating EE certs and signatures for the COSE algorithms
func coseSignature(cn string, manifest []byte, algs []*cose.Algorithm, s *PKCS7Signer) (coseSig []byte, err error) {
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
