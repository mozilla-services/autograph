package apk

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/mozilla-services/autograph/signer"
	"go.mozilla.org/pkcs7"
)

const (
	// Type of this signer is "apk"
	Type = "apk"

	// ZIPMethodCompressAll represents the default option to
	// compress all files in repacked JARs
	ZIPMethodCompressAll = "all"
	// ZIPMethodCompressPassthrough represents the option to pass
	// through all files with their current compression in JARs
	ZIPMethodCompressPassthrough = "passthrough"
)

// An APKSigner is configured to issue PKCS7 detached signatures
// for Android application packages.
type APKSigner struct {
	signer.Configuration
	signingKey        crypto.PrivateKey
	signingCert       *x509.Certificate
	signatureFileName string
	noSignedAttr      bool
}

// New initializes an apk signer using a configuration
func New(conf signer.Configuration) (s *APKSigner, err error) {
	s = new(APKSigner)
	if conf.Type != Type {
		return nil, errors.Errorf("apk: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type
	if conf.ID == "" {
		return nil, errors.New("apk: missing signer ID in signer configuration")
	}
	s.ID = conf.ID
	if conf.PrivateKey == "" {
		return nil, errors.New("apk: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	s.signingKey, err = signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "apk: failed to parse private key")
	}
	block, _ := pem.Decode([]byte(conf.Certificate))
	if block == nil {
		return nil, errors.New("apk: failed to parse certificate PEM")
	}
	s.signingCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "apk: could not parse X.509 certificate")
	}
	// APK signing certs typically have a 30y expiration, which is fairly useless
	// but requires the validity to be correct
	if time.Now().Before(s.signingCert.NotBefore) || time.Now().After(s.signingCert.NotAfter) {
		return nil, errors.New("apk: signer certificate is not currently valid")
	}
	// the name of the signature block file inside the META-INF directory
	// is determined by the private key type
	switch s.signingKey.(type) {
	case *rsa.PrivateKey:
		s.signatureFileName = "SIGNATURE.RSA"
	case *dsa.PrivateKey:
		s.signatureFileName = "SIGNATURE.DSA"
	case *ecdsa.PrivateKey:
		s.signatureFileName = "SIGNATURE.EC"
	}
	// if specified, don't sign with attributes
	s.noSignedAttr = conf.NoPKCS7SignedAttributes
	return
}

// Config returns the configuration of the current signer
func (s *APKSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
	}
}

// SignFile takes an unsigned, unaligned APK in base64 form, generates the JAR manifests
// and calls SignData to sign the signature file using the configured private key.
//
// The PKCS7 detached signature and the manifests are then stored inside the
// ZIP file under META-INF, and the whole archived is aligned. The returned
// data is the signed aligned APK.
//
// This implements apksigning v1, aka jarsigner. apksigning v2 is not supported.
func (s *APKSigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot get options")
	}
	if opt.ZIP == "" {
		opt.ZIP = ZIPMethodCompressAll
	}
	err = validateZIPOption(opt.ZIP)
	if err != nil {
		return nil, errors.Wrap(err, "apk: got invalid ZIP option")
	}

	var (
		signedFile []byte
	)
	manifest, sigfile, err := makeJARManifests(input)
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot make JAR manifests from APK")
	}
	p7sig, err := s.signData(sigfile, options)
	if err != nil {
		return nil, errors.Wrap(err, "apk: failed to sign APK")
	}
	if opt.ZIP == ZIPMethodCompressPassthrough {
		signedFile, err = appendSignatureFilesToJAR(input, manifest, sigfile, p7sig, s.signatureFileName)
		if err != nil {
			return nil, errors.Wrap(err, "apk: failed to append signatures files to APK")
		}
	} else { // opt.ZIP == ZIPMethodCompressAll
		signedFile, err = repackAndAlignJAR(input, manifest, sigfile, p7sig, s.signatureFileName)
		if err != nil {
			return nil, errors.Wrap(err, "apk: failed to repack and align APK")
		}
	}

	return signedFile, nil
}

// SignData takes a JAR signature file and returns a pkcs7 signature
func (s *APKSigner) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	p7sig, err := s.signData(sigfile, options)
	if err != nil {
		return nil, err
	}
	sig := new(Signature)
	sig.Data = p7sig
	sig.Finished = true
	return sig, nil
}

func (s *APKSigner) signData(sigfile []byte, options interface{}) ([]byte, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot get options")
	}
	toBeSigned, err := pkcs7.NewSignedData(sigfile)
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot initialize signed data")
	}
	p7Digest, err := opt.PK7Digest()
	if err != nil {
		return nil, errors.Wrap(err, "apk: error parsing PK7 Digest")
	}
	toBeSigned.SetDigestAlgorithm(p7Digest)
	if s.noSignedAttr {
		// special case for fennec: when signing legacy using RSA and SHA1,
		// set the digest alg to 1.2.840.113549.1.1.1
		// https://bugzilla.mozilla.org/show_bug.cgi?id=1513564
		switch s.signingKey.(type) {
		case *rsa.PrivateKey:
			if p7Digest.Equal(pkcs7.OIDDigestAlgorithmSHA1) {
				toBeSigned.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)
			}
		}
		// old APKs don't support signed attributes, otherwise android returns
		// java.security.SignatureException: APKs with Signed Attributes
		// broken on platforms with API Level < 19
		err = toBeSigned.SignWithoutAttr(s.signingCert, s.signingKey, pkcs7.SignerInfoConfig{})
	} else {
		err = toBeSigned.AddSigner(s.signingCert, s.signingKey, pkcs7.SignerInfoConfig{})
	}
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot sign")
	}
	toBeSigned.Detach()
	p7sig, err := toBeSigned.Finish()
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot finish signing data")
	}
	return p7sig, nil
}

// Signature is a PKCS7 detached signature
type Signature struct {
	p7       *pkcs7.PKCS7
	Data     []byte
	Finished bool
}

// Verify verifies an apk pkcs7 signature
// WARNING: this function does not verify the JAR manifests
func (sig *Signature) Verify() error {
	if !sig.Finished {
		return errors.New("apk.Verify: cannot verify unfinished signature")
	}
	return sig.p7.Verify()
}

// Marshal returns the base64 representation of a PKCS7 detached signature
func (sig *Signature) Marshal() (string, error) {
	if !sig.Finished {
		return "", errors.New("apk: cannot marshal unfinished signature")
	}
	if len(sig.Data) == 0 {
		return "", errors.New("apk: cannot marshal empty signature data")
	}
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Unmarshal takes the base64 representation of a PKCS7 detached signature
// and the content of the signed data, and returns a PKCS7 struct
func Unmarshal(signature string, content []byte) (sig *Signature, err error) {
	sig = new(Signature)
	sig.Data, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return sig, errors.Wrap(err, "apk.Unmarshal: failed to decode base64 signature")
	}
	sig.p7, err = pkcs7.Parse(sig.Data)
	if err != nil {
		return sig, errors.Wrap(err, "apk.Unmarshal: failed to parse pkcs7 signature")
	}
	sig.p7.Content = content
	sig.Finished = true
	return
}

// String returns a PEM encoded PKCS7 block
func (sig *Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}

// Options is empty for this signer type
type Options struct {
	ZIP string `json:"zip"`

	// PKCS7Digest is a string referring to algorithm to use for the PKCS7 signature digest
	PKCS7Digest string `json:"pkcs7_digest"`
}

// GetOptions takes a input interface and reflects it into a struct of options
func GetOptions(input interface{}) (options Options, err error) {
	buf, err := json.Marshal(input)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, &options)
	return
}

// GetDefaultOptions returns default options of the signer
func (s *APKSigner) GetDefaultOptions() interface{} {
	return Options{
		ZIP:         ZIPMethodCompressPassthrough,
		PKCS7Digest: "SHA1",
	}
}

func validateZIPOption(zipOpt string) error {
	switch zipOpt {
	case ZIPMethodCompressAll:
		return nil
	case ZIPMethodCompressPassthrough:
		return nil
	default:
		return errors.Errorf("Invalid APK ZIP option")
	}
}

// PK7Digest validates and return an ASN OID for a PKCS7 digest
// algorithm or an error. If no specific digest is specific, SHA256 is used.
func (o *Options) PK7Digest() (asn1.ObjectIdentifier, error) {
	if o == nil {
		return nil, errors.New("apk: Cannot get PK7Digest from nil Options")
	}
	switch strings.ToUpper(o.PKCS7Digest) {
	case "SHA1":
		return pkcs7.OIDDigestAlgorithmSHA1, nil
	case "SHA384":
		return pkcs7.OIDDigestAlgorithmSHA384, nil
	case "SHA512":
		return pkcs7.OIDDigestAlgorithmSHA512, nil
	default:
		return pkcs7.OIDDigestAlgorithmSHA256, nil
	}
}
