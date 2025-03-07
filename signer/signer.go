// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package signer // import "github.com/mozilla-services/autograph/signer"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/mozilla-services/autograph/database"
	"github.com/mozilla-services/autograph/formats"

	"github.com/mozilla-services/autograph/crypto11"
)

// IDFormat is a regex for the format IDs must follow
const IDFormat = `^[a-zA-Z0-9-_]{1,64}$`

// RecommendationConfig is a config for the XPI recommendation file
type RecommendationConfig struct {
	// AllowedStates is a map of strings the signer is allowed to
	// set in the recommendations file to true indicating whether
	// they're allowed or not
	AllowedStates map[string]bool `yaml:"states,omitempty"`

	// FilePath is the path in the XPI to save the recommendations
	// file
	FilePath string `yaml:"path,omitempty"`

	// ValidityRelativeStart is when to set the recommendation
	// validity not_before relative to now
	ValidityRelativeStart time.Duration `yaml:"relative_start,omitempty"`

	// ValidityDuration is when to set the recommendation validity
	// not_after relative to now
	//
	// i.e.
	//         ValidityRelativeStart    ValidityDuration
	//       <----------------------> <------------------->
	//      |                        |                     |
	//   not_before          now / signing TS          not_after
	ValidityDuration time.Duration `yaml:"duration,omitempty"`
}

// Configuration defines the parameters of a signer.
type Configuration struct {
	ID            string            `json:"id" yaml:"id"`
	Type          string            `json:"type" yaml:"type"`
	Mode          string            `json:"mode" yaml:"mode"`
	PrivateKey    string            `json:"privatekey,omitempty" yaml:"privatekey,omitempty"`
	PublicKey     string            `json:"publickey,omitempty" yaml:"publickey,omitempty"`
	IssuerPrivKey string            `json:"issuerprivkey,omitempty" yaml:"issuerprivkey,omitempty"`
	IssuerCert    string            `json:"issuercert,omitempty" yaml:"issuercert,omitempty"`
	Certificate   string            `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	DB            *database.Handler `json:"-" yaml:"-"`

	// X5U (X.509 URL) is a URL that points to an X.509 public key
	// certificate chain to validate a content signature
	X5U string `json:"x5u,omitempty" yaml:"x5u,omitempty"`

	// RecommendationConfig specifies config values for
	// recommendations files for XPI signers
	RecommendationConfig RecommendationConfig `yaml:"recommendation,omitempty"`

	// NoPKCS7SignedAttributes for signing legacy APKs don't sign
	// attributes and use a legacy PKCS7 digest
	NoPKCS7SignedAttributes bool `json:"nopkcs7signedattributes,omitempty" yaml:"nopkcs7signedattributes,omitempty"`

	// KeyID is the fingerprint of the gpg key or subkey to use
	// e.g. 0xA2B637F535A86009 for the gpg2 signer type
	KeyID string `json:"keyid,omitempty" yaml:"keyid,omitempty"`

	// SubdomainOverride is to override the subdomain of the leaf certificates
	// created. This is mostly for contentsignaturepki. If this isn't set, the
	// `KeyID` is used as the subdomain, instead. When setting this value to
	// match another extant signer id, also be sure to set the X5U and
	// ChainUploadLocations of this signer configuration to avoid uploading
	// chains that share the same file name.
	SubdomainOverride string `json:"subdomain_override,omitempty" yaml:"subdomainoverride,omitempty"`

	// Passphrase is the optional passphrase to use decrypt the
	// gpg secret key for the gpg2 signer type
	Passphrase string `json:"passphrase,omitempty" yaml:"passphrase,omitempty"`

	// Validity is the lifetime of a end-entity certificate
	Validity time.Duration `json:"validity,omitempty" yaml:"validity,omitempty"`

	// ClockSkewTolerance increase the lifetime of a certificate
	// to account for clients with skewed clocks by adding days
	// to the notbefore and notafter values. For example, a certificate
	// with a validity of 30d and a clock skew tolerance of 10 days will
	// have a total validity of 10+30+10=50 days.
	ClockSkewTolerance time.Duration `json:"clock_skew_tolerance,omitempty" yaml:"clockskewtolerance,omitempty"`

	// ChainUploadLocation is the target a certificate chain should be
	// uploaded to in order for clients to find it at the x5u location.
	ChainUploadLocation string `json:"chain_upload_location,omitempty" yaml:"chainuploadlocation,omitempty"`

	// CaCert is the certificate of the root of the pki, when used
	CaCert string `json:"cacert,omitempty" yaml:"cacert,omitempty"`

	// Hash is a hash algorithm like 'sha1' or 'sha256'
	Hash string `json:"hash,omitempty" yaml:"hash,omitempty"`

	// SaltLength controls the length of the salt used in a RSA PSS
	// signature. It can either be a number of bytes, or one of the special
	// PSSSaltLength constants from the rsa package.
	SaltLength int `json:"saltlength,omitempty" yaml:"saltlength,omitempty"`

	// SignerOpts contains options for signing with a Signer
	SignerOpts crypto.SignerOpts `json:"signer_opts,omitempty" yaml:"signeropts,omitempty"`

	isHsmAvailable bool
	Hsm            HSM
}

// InitHSM indicates that an HSM has been initialized
func (cfg *Configuration) InitHSM(hsm HSM) {
	cfg.isHsmAvailable = true
	cfg.Hsm = hsm
}

// Signer is an interface to a configurable issuer of digital signatures
type Signer interface {
	Config() Configuration
}

// StatefulSigner is an interface to an issuer of digital signatures
// that stores out of memory state (files, HSM or DB connections,
// etc.) to clean up at exit
type StatefulSigner interface {
	AtExit() error
}

// HashSigner is an interface to a signer able to sign hashes
type HashSigner interface {
	SignHash(data []byte, options interface{}) (Signature, error)
	GetDefaultOptions() interface{}
}

// DataSigner is an interface to a signer able to sign raw data
type DataSigner interface {
	SignData(data []byte, options interface{}) (Signature, error)
	GetDefaultOptions() interface{}
}

// FileSigner is an interface to a signer able to sign files
type FileSigner interface {
	SignFile(file []byte, options interface{}) (SignedFile, error)
	GetDefaultOptions() interface{}
}

// MultipleFileSigner is an interface to a signer that signs multiple
// files in one signing operation
type MultipleFileSigner interface {
	SignFiles(files []NamedUnsignedFile, options interface{}) ([]NamedSignedFile, error)
	GetDefaultOptions() interface{}
}

// Signature is an interface to a digital signature
type Signature interface {
	Marshal() (signature string, err error)
}

// SignedFile is an []bytes that contains file data
type SignedFile []byte

type namedFile struct {
	Name  string
	Bytes []byte
}

// NamedUnsignedFile is a file with a name to sign
type NamedUnsignedFile namedFile

// NamedSignedFile is a file with a name that's been signed
type NamedSignedFile namedFile

// isValidUnsignedFilename
func isValidUnsignedFilename(filename string) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9]`).MatchString(filename) {
		return fmt.Errorf("unsigned filename must start with an alphanumeric character")
	}
	if !regexp.MustCompile(`[a-zA-Z0-9]$`).MatchString(filename) {
		return fmt.Errorf("unsigned filename must end with an alphanumeric character")
	}
	// support debian version conventions as documented at:
	//    https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
	if !regexp.MustCompile(`^[-_\.+~a-zA-Z0-9]{1,256}$`).MatchString(filename) {
		return fmt.Errorf(`unsigned filename must match ^[-_\.+~a-zA-Z0-9]{1,256}$`)
	}
	if regexp.MustCompile(`\.\.`).MatchString(filename) {
		return fmt.Errorf("unsigned filename must not include '..'")
	}
	return nil
}

// NewNamedUnsignedFile allocates and returns a ref to a new
// NamedUnsignedFile from a REST format SigningFile. It base64 decodes
// the REST SigningFile.Content into NamedUnsignedFile.Bytes.
func NewNamedUnsignedFile(restSigningFile formats.SigningFile) (*NamedUnsignedFile, error) {
	if err := isValidUnsignedFilename(restSigningFile.Name); err != nil {
		return nil, fmt.Errorf("invalid named file name: %w", err)
	}
	fileBytes, err := base64.StdEncoding.DecodeString(restSigningFile.Content)
	if err != nil {
		return nil, err
	}
	return &NamedUnsignedFile{
		Name:  restSigningFile.Name,
		Bytes: fileBytes,
	}, nil
}

// RESTSigningFile allocates and returns a ref to a new REST
// SigningFile from a NamedSignedFile. It base64 encodes
// NamedSignedFile.Bytes into the REST SigningFile.Content.
func (nsf *NamedSignedFile) RESTSigningFile() *formats.SigningFile {
	return &formats.SigningFile{
		Name:    nsf.Name,
		Content: base64.StdEncoding.EncodeToString(nsf.Bytes),
	}
}

// TestFileGetter returns a test file a signer will accept in its
// SignFile interface
type TestFileGetter interface {
	GetTestFile() (testfile []byte)
}

// GetRand returns a cryptographically secure random number from the
// HSM if available and otherwise rand.Reader
func (cfg *Configuration) GetRand() io.Reader {
	if cfg.isHsmAvailable {
		return cfg.Hsm.GetRand()
	}
	return rand.Reader
}

// GetKeys parses a configuration to retrieve the private and public
// key of a signer, and a marshalled public key. It fetches keys from
// the HSM when possible.
func (cfg *Configuration) GetKeys() (priv crypto.PrivateKey, pub crypto.PublicKey, publicKey string, err error) {
	priv, err = cfg.GetPrivateKey()
	if err != nil {
		return
	}

	var (
		publicKeyBytes []byte
		unmarshaledPub crypto.PublicKey
	)

	switch privateKey := priv.(type) {
	case *rsa.PrivateKey:
		pub = privateKey.Public()
		unmarshaledPub = &privateKey.PublicKey

	case *ecdsa.PrivateKey:
		pub = privateKey.Public()
		unmarshaledPub = &privateKey.PublicKey

	case *crypto11.PKCS11PrivateKeyECDSA:
		pub = privateKey.Public()
		unmarshaledPub = privateKey.PubKey.(*ecdsa.PublicKey)

	case *crypto11.PKCS11PrivateKeyRSA:
		pub = privateKey.Public()
		unmarshaledPub = privateKey.PubKey.(*rsa.PublicKey)

	default:
		err = fmt.Errorf("unsupported private key type %T", priv)
		return
	}

	publicKeyBytes, err = x509.MarshalPKIXPublicKey(unmarshaledPub)
	if err != nil {
		err = fmt.Errorf("failed to asn1 marshal %T public key: %w", unmarshaledPub, err)
		return
	}
	publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)
	if len(publicKey) < 50 {
		err = fmt.Errorf("encoded public key is shorter than 50char, which is impossible: %q", publicKey)
		return
	}
	return
}

// GetPrivateKey uses a signer configuration to determine where a private
// key should be accessed from. If it is in local configuration, it will
// be parsed and loaded in the signer. If it is in an HSM, this will be
// outsourced to `cfg.Hsm`, which knows how to locate a private key handle
// in an HSM. Either way, the returned value implements the crypto.Sign
// interface.
func (cfg *Configuration) GetPrivateKey() (crypto.PrivateKey, error) {
	cfg.PrivateKey = removePrivateKeyNewlines(cfg.PrivateKey)
	if cfg.PrivateKeyHasPEMPrefix() {
		return ParsePrivateKey([]byte(cfg.PrivateKey))
	}
	// otherwise, we assume the privatekey represents a label in the HSM
	if cfg.isHsmAvailable {
		key, err := cfg.Hsm.GetPrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, fmt.Errorf("no suitable key found")
}

// ParsePrivateKey takes a PEM blocks are returns a crypto.PrivateKey
// It tries to parse as many known key types as possible before failing and
// returning all the errors it encountered.
func ParsePrivateKey(keyPEMBlock []byte) (key crypto.PrivateKey, err error) {
	var (
		keyDERBlock       *pem.Block
		skippedBlockTypes []string
	)
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return nil, fmt.Errorf("signer: found a certificate rather than a key in the PEM for the private key")
			}
			return nil, fmt.Errorf("signer: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes)

		}
		if strings.HasSuffix(keyDERBlock.Type, "PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
	// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
	// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
	// Code taken from the crypto/tls standard library.
	if key, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	var savedErr []string
	savedErr = append(savedErr, "pkcs1: "+err.Error())
	if key, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		}
	}
	savedErr = append(savedErr, "pkcs8: "+err.Error())

	if key, err = x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	savedErr = append(savedErr, "ecdsa: "+err.Error())

	return nil, errors.New("failed to parse private key, make sure to use PKCS1 for RSA and PKCS8 for ECDSA. errors: " + strings.Join(savedErr, ";;; "))
}

func removePrivateKeyNewlines(confPrivateKey string) string {
	// make sure heading newlines are removed
	removeNewlines := regexp.MustCompile(`^(\r?\n)`)
	return removeNewlines.ReplaceAllString(confPrivateKey, "")
}

// PrivateKeyHasPEMPrefix returns whether the signer configuration
// prefix begins with `-----BEGIN` (indicating a PEM block) after
// stripping newlines
func (cfg *Configuration) PrivateKeyHasPEMPrefix() bool {
	// if a private key in the config starts with a PEM header, it is
	// defined locally and is parsed and returned
	return strings.HasPrefix(removePrivateKeyNewlines(cfg.PrivateKey), "-----BEGIN")
}

// CheckHSMConnection is the default implementation of
// CheckHSMConnection (exposed via the signer.Configuration
// interface).  It tried to fetch the signer private key and errors if
// that fails or the private key is not an HSM key handle.
// Ideally this would be part of the HSM interface, but the check requires
// the label of a key on the HSM, which is part of the Configuration
func (cfg *Configuration) CheckHSMConnection() error {
	if cfg.PrivateKeyHasPEMPrefix() {
		return fmt.Errorf("private key for signer %s has a PEM prefix and is not an HSM key label", cfg.ID)
	}
	if !cfg.isHsmAvailable {
		return fmt.Errorf("HSM is not available for signer %s", cfg.ID)
	}

	_, err := cfg.GetPrivateKey()
	if err != nil {
		return fmt.Errorf("error fetching private key for signer %s: %w", cfg.ID, err)
	}
	return nil
}

// MakeKey generates a new key of type keyTpl and returns the private and
// public interfaces. If an HSM is available, this is outsourced to `cfg.Hsm`,
// which will generate them in an HSM instead of in memory.
func (cfg *Configuration) MakeKey(keyTpl interface{}, keyName string) (priv crypto.PrivateKey, pub crypto.PublicKey, err error) {
	if cfg.isHsmAvailable {
		return cfg.Hsm.MakeKey(keyTpl, keyName)
	}
	// no hsm, make keys in memory
	switch keyTplType := keyTpl.(type) {
	case *ecdsa.PublicKey:
		switch keyTplType.Params().Name {
		case "P-256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P-384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		default:
			return nil, nil, fmt.Errorf("unsupported curve %q",
				keyTpl.(*ecdsa.PublicKey).Params().Name)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ecdsa key in memory: %w", err)
		}
		pub = priv.(*ecdsa.PrivateKey).Public()
		return
	case *rsa.PublicKey:
		keySize := keyTplType.Size()
		priv, err = rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate rsa key in memory: %w", err)
		}
		pub = priv.(*rsa.PrivateKey).Public()
		return
	default:
		return nil, nil, fmt.Errorf("making key of type %T is not supported", keyTpl)
	}
}
