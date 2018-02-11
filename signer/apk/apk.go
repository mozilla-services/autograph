package apk

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/pkcs7"
)

const (
	// Type of this signer is "apk"
	Type = "apk"
)

// An APKSigner is configured to issue PKCS7 detached signatures
// for Android application packages.
type APKSigner struct {
	signer.Configuration
	signingKey  crypto.PrivateKey
	signingCert *x509.Certificate
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

// SignData takes an unsigned, unaligned APK in base64 form, generates the JAR manifests
// and signs the signature file using the configured private key. The PKCS7 detached signature
// and the manifests are then stored inside the ZIP file under META-INF, and the whole
// archived is aligned. The returned data is the signed aligned APK.
//
// This implements apksigning v1, aka jarsigner. apksigning v2 is not supported.
func (s *APKSigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	var signedFile []byte
	manifest, sigfile, err := makeJARManifests(input)
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot make JAR manifests from APK")
	}
	p7sig := new(Signature)
	toBeSigned, err := pkcs7.NewSignedData(sigfile)
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot initialize signed data")
	}

	// APKs are signed with SHA256
	toBeSigned.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	err = toBeSigned.AddSigner(s.signingCert, s.signingKey, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot sign")
	}
	toBeSigned.Detach()
	p7sig.Data, err = toBeSigned.Finish()
	if err != nil {
		return nil, errors.Wrap(err, "apk: cannot finish signing data")
	}
	p7sig.Finished = true

	signedFile, err = repackAndAlignJAR(input, manifest, sigfile, p7sig.Data)
	if err != nil {
		return nil, errors.Wrap(err, "apk: failed to repack and align APK")
	}

	return signedFile, nil
}

// Signature is a PKCS7 detached signature
type Signature struct {
	p7       *pkcs7.PKCS7
	Data     []byte
	Finished bool
}

// Verify verifies an apk signature
func (sig *Signature) Verify() error {
	if !sig.Finished {
		return errors.New("apk.Verify: cannot verify unfinished signature")
	}
	return sig.p7.Verify()
}

// String returns a PEM encoded PKCS7 block
func (sig *Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}

// Options is empty for this signer type
type Options struct{}

// GetDefaultOptions returns default options of the signer
func (s *APKSigner) GetDefaultOptions() interface{} {
	return Options{}
}
