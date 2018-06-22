package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/pkcs7"
	"go.mozilla.org/cose"
)

const (
	// Type of this signer is "xpi"
	Type = "xpi"

	// ModeAddOn represents a signer that issues signatures for
	// regular firefox add-ons and web extensions developed by anyone
	ModeAddOn = "add-on"

	// ModeExtension represents a signer that issues signatures for
	// internal extensions developed by Mozilla
	ModeExtension = "extension"

	// ModeSystemAddOn represents a signer that issues signatures for
	// System Add-Ons developed by Mozilla
	ModeSystemAddOn = "system add-on"

	// ModeHotFix represents a signer that issues signatures for
	// Firefox HotFixes
	ModeHotFix = "hotfix"
)

// A PKCS7Signer is configured to issue PKCS7 detached signatures
// for Firefox Add-ons of various types.
type PKCS7Signer struct {
	signer.Configuration
	issuerKey  crypto.PrivateKey
	issuerCert *x509.Certificate

	// OU is the organizational unit of the end-entity certificate
	// generated for each operation performed by this signer
	OU string

	// EndEntityCN is the subject CN of the end-entity certificate generated
	// for each operation performed by this signer. Most of the time
	// the ID will be left blank and provided by the requester of the
	// signature, but for hotfix signers, it is set to a specific value.
	EndEntityCN string

	// rsa cache is used to pre-generate RSA private keys and speed up
	// the signing process
	rsaCache chan *rsa.PrivateKey
}

// New initializes an XPI signer using a configuration
func New(conf signer.Configuration) (s *PKCS7Signer, err error) {
	s = new(PKCS7Signer)
	if conf.Type != Type {
		return nil, errors.Errorf("xpi: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type
	if conf.ID == "" {
		return nil, errors.New("xpi: missing signer ID in signer configuration")
	}
	s.ID = conf.ID
	if conf.PrivateKey == "" {
		return nil, errors.New("xpi: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	s.issuerKey, err = signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to parse private key")
	}
	block, _ := pem.Decode([]byte(conf.Certificate))
	if block == nil {
		return nil, errors.New("xpi: failed to parse certificate PEM")
	}
	s.issuerCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: could not parse X.509 certificate")
	}
	// some sanity checks for the signer cert
	if !s.issuerCert.IsCA {
		return nil, errors.New("xpi: signer certificate must have CA constraint set to true")
	}
	if time.Now().Before(s.issuerCert.NotBefore) || time.Now().After(s.issuerCert.NotAfter) {
		return nil, errors.New("xpi: signer certificate is not currently valid")
	}
	if s.issuerCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("xpi: signer certificate is missing certificate signing key usage")
	}
	hasCodeSigning := false
	for _, eku := range s.issuerCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return nil, errors.New("xpi: signer certificate does not have code signing EKU")
	}
	switch conf.Mode {
	case ModeAddOn:
		s.OU = "Production"
	case ModeExtension:
		s.OU = "Mozilla Extensions"
	case ModeSystemAddOn:
		s.OU = "Mozilla Components"
	case ModeHotFix:
		// FIXME: this also needs to pin the signing key somehow
		s.OU = "Production"
		s.EndEntityCN = "firefox-hotfix@mozilla.org"
	default:
		return nil, errors.Errorf("xpi: unknown signer mode %q, must be 'add-on', 'extension', 'system add-on' or 'hotfix'", conf.Mode)
	}
	s.Mode = conf.Mode

	// If the private key is rsa, launch a go routine that populates
	// the rsa cache with private keys of the same length
	if issuerPrivateKey, ok := s.issuerKey.(*rsa.PrivateKey); ok {
		s.rsaCache = make(chan *rsa.PrivateKey, 100)
		go s.populateRsaCache(s.issuerKey.(*rsa.PrivateKey).N.BitLen())

		if issuerPrivateKey.N.BitLen() < 2048 {
			return nil, errors.Errorf("xpi: issuer RSA key must be at least 2048 bits")
		}
	}

	return
}

// Config returns the configuration of the current signer
func (s *PKCS7Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		Mode:        s.Mode,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
	}
}

// SignFile takes an unsigned zipped XPI file and returns a signed XPI file
func (s *PKCS7Signer) SignFile(input []byte, options interface{}) (signedFile signer.SignedFile, err error) {
	var (
		pkcs7Manifest []byte
		manifest []byte
		metas = []Metafile{}
		opt Options
		coseSig []byte
		coseSigAlgs []*cose.Algorithm
	)

	opt, err = GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot get options")
	}
	coseSigAlgs, err = opt.Algorithms()
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot make JAR manifest from XPI")
	}

	manifest, err = makeJARManifest(input)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot make JAR manifest from XPI")
	}

	if len(coseSigAlgs) < 1 {
		pkcs7Manifest = manifest
	} else {
		coseSig, err = s.signData(manifest, opt)
		if err != nil {
			return nil, errors.Wrap(err, "xpi: error signing cose message")
		}

		// add the cose files to the metafiles we'll add to the XPI
		coseMetaFiles := []Metafile{
			{"META-INF/cose.manifest", manifest},
			{"META-INF/cose.sig", coseSig},
		}
		metas = append(metas, coseMetaFiles...)

		// add entries for the cose files to the manifest as cose.manifest and cose.sig
		pkcs7Manifest, err = makePKCS7Manifest(input, metas)
		if err != nil {
			return nil, errors.Wrap(err, "xpi: error making PKCS7 manifest")
		}
	}

	sigfile, err := makeJARSignature(pkcs7Manifest)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot make JAR manifest signature from XPI")
	}

	opt.COSEAlgorithms = []string{}
	p7sig, err := s.signData(sigfile, opt)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to sign XPI")
	}

	metas = append(metas, []Metafile{
		{"META-INF/manifest.mf", pkcs7Manifest},
		{"META-INF/mozilla.sf", sigfile},
		{"META-INF/mozilla.rsa", p7sig},
	}...)

	signedFile, err = repackJARWithMetafiles(input, metas)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: failed to repack XPI")
	}
	return signedFile, nil
}

// SignData takes an input signature file and returns a PKCS7 or COSE detached signature
func (s *PKCS7Signer) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot get options")
	}
	sigBytes, err := s.signData(sigfile, opt)
	if err != nil {
		return nil, err
	}
	sig := new(Signature)
	sig.Data = sigBytes
	sig.Finished = true
	return sig, nil
}

func (s *PKCS7Signer) signData(sigfile []byte, opt Options) ([]byte, error) {
	cn, err := opt.CN(s)
	if err != nil {
		return nil, err
	}
	coseSigAlgs, err := opt.Algorithms()
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot make JAR manifest from XPI")
	}

	if len(coseSigAlgs) < 1 {
		eeCert, eeKey, err := s.MakeEndEntity(cn, nil)
		if err != nil {
			return nil, err
		}

		toBeSigned, err := pkcs7.NewSignedData(sigfile)
		if err != nil {
			return nil, errors.Wrap(err, "xpi: cannot initialize signed data")
		}
		// XPIs are signed with SHA1
		toBeSigned.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA1)
		err = toBeSigned.AddSignerChain(eeCert, eeKey, []*x509.Certificate{s.issuerCert}, pkcs7.SignerInfoConfig{})
		if err != nil {
			return nil, errors.Wrap(err, "xpi: cannot sign")
		}
		toBeSigned.Detach()
		p7sig, err := toBeSigned.Finish()
		if err != nil {
			return nil, errors.Wrap(err, "xpi: cannot finish signing data")
		}
		return p7sig, nil
	} else {
		coseSig, err := coseSignature(cn, sigfile, coseSigAlgs, s)
		if err != nil {
			return nil, errors.Wrap(err, "xpi: error signing cose message")
		}
		return coseSig, nil
	}
}

// Options contains specific parameters used to sign XPIs
type Options struct {
	// ID is the add-on ID which is stored in the end-entity subject CN
	ID string `json:"id"`

	// COSEAlgorithms is a list of strings referring to IANA algorithms to use for COSE signatures
	COSEAlgorithms []string `json:"cose_algorithms"`
}

// CN returns the common name
func (o *Options) CN(s *PKCS7Signer) (cn string, err error) {
	if o == nil {
		err = errors.New("xpi: cannot get common name from nil Options")
	}

	cn = o.ID
	if s.EndEntityCN != "" {
		cn = s.EndEntityCN
	}

	if cn == "" {
		err = errors.New("xpi: missing common name")
	}
	return
}

// Algorithms validates and returns COSE algorithms
func (o *Options) Algorithms() (algs []*cose.Algorithm, err error) {
	if o == nil {
		err = errors.New("xpi: cannot get COSE Algorithms from nil Options")
	}

	for _, algStr := range o.COSEAlgorithms {
		alg := stringToCOSEAlg(algStr)
		if alg == nil {
			return nil, errors.Wrapf(err, "xpi: invalid or unsupported COSE algorithm %s", algStr)
		}
		algs = append(algs, alg)
	}
	return
}

// GetDefaultOptions returns default options of the signer
func (s *PKCS7Signer) GetDefaultOptions() interface{} {
	return Options{ID: "ffffffff-ffff-ffff-ffff-ffffffffffff"}
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

// Signature is a detached PKCS7 signature or COSE SignMessage
type Signature struct {
	p7          *pkcs7.PKCS7
	signMessage *cose.SignMessage
	Data        []byte
	Finished    bool
}

// Marshal returns the base64 representation of a PKCS7 detached signature
func (sig *Signature) Marshal() (string, error) {
	if !sig.Finished {
		return "", errors.New("xpi: cannot marshal unfinished signature")
	}
	if len(sig.Data) == 0 {
		return "", errors.New("xpi: cannot marshal empty signature data")
	}
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Unmarshal takes the base64 representation of a PKCS7 detached signature
// and the content of the signed data, and returns a PKCS7 struct
func Unmarshal(signature string, content []byte) (sig *Signature, err error) {
	sig = new(Signature)
	sig.Data, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return sig, errors.Wrap(err, "xpi.Unmarshal: failed to decode base64 signature")
	}
	sig.p7, err = pkcs7.Parse(sig.Data)
	if err != nil {
		return sig, errors.Wrap(err, "xpi.Unmarshal: failed to parse pkcs7 signature")
	}
	sig.p7.Content = content
	sig.Finished = true
	return
}

// VerifyWithChain verifies an xpi signature using the provided truststore
func (sig *Signature) VerifyWithChain(truststore *x509.CertPool) error {
	if !sig.Finished {
		return errors.New("xpi.VerifyWithChain: cannot verify unfinished signature")
	}
	return sig.p7.VerifyWithChain(truststore)
}

// String returns a PEM encoded PKCS7 block
func (sig *Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}

// verifyPKCS7SignatureRoundTrip checks that
//
// 1) the signed XPI includes a PKCS7 signature and signature data
// 2) the signature serializes and deserializes properly
// 3) the PKCS7 signatures
// 4) the signature cert chain verifies when an optional non-nil truststore is provided
//
func verifyPKCS7SignatureRoundTrip(signedFile signer.SignedFile, truststore *x509.CertPool) error {
	sigStrBytes, err := readFileFromZIP(signedFile, "META-INF/mozilla.rsa")
	if err != nil {
		return errors.Wrapf(err, "failed to read PKCS7 signature META-INF/mozilla.rsa")
	}
	sigStr := base64.StdEncoding.EncodeToString(sigStrBytes)
	sigData, err := readFileFromZIP(signedFile, "META-INF/mozilla.sf")
	if err != nil {
		return errors.Wrapf(err, "failed to read META-INF/mozilla.sf")
	}

	// convert string format back to signature
	sig, err := Unmarshal(sigStr, sigData)
	if err != nil {
		return errors.Wrapf(err, "failed to unmarshal PKCS7 signature")
	}
	// verify signature on input data
	if sig.VerifyWithChain(truststore) != nil {
		return fmt.Errorf("failed to verify xpi signature: %v", sig.VerifyWithChain(truststore))
	}

	// make sure we still have the same string representation
	sigStr2, err := sig.Marshal()
	if err != nil {
		return fmt.Errorf("failed to re-marshal signature: %v", err)
	}
	if sigStr != sigStr2 {
		return fmt.Errorf("marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
			sigStr, sigStr2)
	}
	return nil
}

// VerifySignedFile checks the XPI's PKCS7 signature and COSE
// signatures if present
func VerifySignedFile(signedFile signer.SignedFile, truststore *x509.CertPool, opts Options) error {
	err := verifyPKCS7SignatureRoundTrip(signedFile, truststore)
	if err != nil {
		return errors.Wrap(err, "xpi: error verifying PKCS7 signature for signed file")
	}

	if len(opts.COSEAlgorithms) > 0 {
		err = verifyCOSESignatures(signedFile, opts)
		return errors.Wrap(err, "xpi: error verifying COSE signatures for signed file")
	}

	return nil
}
