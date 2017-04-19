package xpi // import "go.mozilla.org/autograph/signer/xpi"

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/pkcs7"
)

const (
	// Type of this signer is "xpi"
	Type = "xpi"

	// CategoryAddOn represents a signer that issues signatures for
	// regular firefox add-ons and web extensions developed by anyone
	CategoryAddOn = "add-on"

	// CategoryExtension represents a signer that issues signatures for
	// internal extensions developed by Mozilla
	CategoryExtension = "extension"

	// CategorySystemAddOn represents a signer that issues signatures for
	// System Add-Ons developed by Mozilla
	CategorySystemAddOn = "system add-on"

	// CategoryHotFix represents a signer that issues signatures for
	// Firefox HotFixes
	CategoryHotFix = "hotfix"
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
}

// New initializes an XPI signer using a configuration
func New(conf signer.Configuration) (s *PKCS7Signer, err error) {
	s = new(PKCS7Signer)
	if conf.Type != Type {
		return nil, errors.Errorf("xpi: invalid usage %q, must be 'xpi'", conf.Type)
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
	if s.issuerCert.NotBefore.After(time.Now()) || s.issuerCert.NotAfter.Before(time.Now()) {
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
	switch conf.Category {
	case CategoryAddOn:
		s.OU = "Production"
	case CategoryExtension:
		s.OU = "Mozilla Extensions"
	case CategorySystemAddOn:
		s.OU = "Mozilla Components"
	case CategoryHotFix:
		// FIXME: this also needs to pin the signing key somehow
		s.OU = "Production"
		s.EndEntityCN = "firefox-hotfix@mozilla.org"
	default:
		return nil, errors.Errorf("xpi: unknown signer category %q, must be 'add-on', 'extension', 'system add-on' or 'hotfix'", conf.Category)
	}
	return
}

// Config returns the configuration of the current signer
func (s *PKCS7Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
		Category:    s.Category,
	}
}

// SignData takes input data and returns a PKCS7 detached signature
func (s *PKCS7Signer) SignData(input []byte, options interface{}) (signer.Signature, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot get options")
	}
	cn := opt.ID
	if s.EndEntityCN != "" {
		cn = s.EndEntityCN
	}
	if cn == "" {
		return nil, errors.New("xpi: missing common name")
	}
	eeCert, eeKey, err := s.MakeEndEntity(cn)
	if err != nil {
		return nil, err
	}
	p7sig := new(PKCS7Signature)
	toBeSigned, err := pkcs7.NewSignedData(input)
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot initialize signed data")
	}
	err = toBeSigned.AddSignerChain(eeCert, eeKey, []*x509.Certificate{s.issuerCert}, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot sign")
	}
	toBeSigned.Detach()
	p7sig.Data, err = toBeSigned.Finish()
	if err != nil {
		return nil, errors.Wrap(err, "xpi: cannot finish signing data")
	}
	p7sig.Finished = true
	return p7sig, nil
}

// Options contains specific parameters used to sign XPIs
type Options struct {
	// ID is the add-on ID which is stored in the end-entity subject CN
	ID string `json:"id"`
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

// PKCS7Signature is a PKCS7 detached signature
type PKCS7Signature struct {
	Data     []byte
	Finished bool
}

// Marshal returns the base64 representation of a PKCS7 detached signature
func (sig *PKCS7Signature) Marshal() (string, error) {
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
func Unmarshal(signature string, content []byte) (sig *pkcs7.PKCS7, err error) {
	sig = new(pkcs7.PKCS7)
	data, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return sig, errors.Wrap(err, "xpi.Unmarshal: failed to decode base64 signature")
	}
	sig, err = pkcs7.Parse(data)
	if err != nil {
		return sig, errors.Wrap(err, "xpi.Unmarshal: failed to parse pkcs7 signature")
	}
	sig.Content = content
	return
}

// String returns a PEM encoded PKCS7 block
func (sig *PKCS7Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}
