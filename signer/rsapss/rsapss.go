package rsapss

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
)

const (
	// Type of this signer is "rsapss"
	Type = "rsapss"
)

// RSAPSSSigner holds the configuration of the signer
type RSAPSSSigner struct {
	signer.Configuration

	// key is the parsed RSA private key to sign hashes
	key *rsa.PrivateKey
}

// New initializes a pgp signer using a configuration
func New(conf signer.Configuration) (s *RSAPSSSigner, err error) {
	s = new(RSAPSSSigner)

	if conf.Type != Type {
		return nil, errors.Errorf("rsapss: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, errors.New("rsapss: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	if conf.PublicKey == "" {
		return nil, errors.New("rsapss: missing public key in signer configuration")
	}
	s.PublicKey = base64.StdEncoding.EncodeToString([]byte(conf.PublicKey))

	if conf.PrivateKey == "" {
		return nil, errors.New("rsapss: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	parsedPrivateKey, err := signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "rsapss: failed to parse private key")
	}
	rsaKey, ok := parsedPrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.Errorf("rsapss: parsed private key is not RSA")
	}
	s.key = rsaKey

	return s, nil
}

// Config returns the configuration of the current signer
func (s *RSAPSSSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
	}
}

// SignData takes data hashes it and returns a signed base64 encoded hash
func (s *RSAPSSSigner) SignData(data []byte, options interface{}) (signer.Signature, error) {
	h := sha1.New()
	h.Write(data)
	digest := h.Sum(nil)
	return s.SignHash(digest, options)
}

// SignHash takes an input hash and returns a signed base64 encoded hash
func (s *RSAPSSSigner) SignHash(digest []byte, options interface{}) (signer.Signature, error) {
	if len(digest) != 20 {
		return nil, errors.Errorf("rsapss: refusing to sign input hash. Got length %d, expected 20.", len(digest))
	}

	sigBytes, err := rsa.SignPSS(rand.Reader, s.key, crypto.SHA1, digest, nil)
	if err != nil {
		return nil, errors.Wrap(err, "rsapss: error signing hash")
	}

	sig := new(Signature)
	sig.Data = sigBytes
	return sig, nil
}

// Signature is a rsapss signature
type Signature struct {
	Data []byte
}

// Marshal returns the base64 representation of a signature
func (sig *Signature) Marshal() (string, error) {
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Unmarshal
func Unmarshal(sigstr string) (signer.Signature, error) {
	sig := new(Signature)
	sigBytes, err := base64.StdEncoding.DecodeString(sigstr)
	if err != nil {
		return nil, err
	}
	sig.Data = sigBytes
	return sig, nil
}

// Options are not implemented for this signer
type Options struct {
}

// GetDefaultOptions returns default options of the signer
func (s *RSAPSSSigner) GetDefaultOptions() interface{} {
	return Options{}
}

// VerifySignature verifies a rsapss signature for the given SHA1
// digest for the given RSA public and signature bytes
func VerifySignature(pubKey *rsa.PublicKey, digest, sigBytes []byte) error {
	err := rsa.VerifyPSS(pubKey, crypto.SHA1, digest, sigBytes, nil)
	return errors.Wrapf(err, "rsapss: failed to verify signature")
}

// VerifySignatureFromB64 verifies a signature from base64 encoded
// digest, signature, and public key as autograph returns from its API
// used in the client and monitor
func VerifySignatureFromB64(b64Input, b64Signature, b64PubKey string) error {
	digest, err := base64.StdEncoding.DecodeString(b64Input)
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(b64Signature)
	if err != nil {
		return err
	}

	rawKey, err := base64.StdEncoding.DecodeString(b64PubKey)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return fmt.Errorf("failed to parse public key PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected rsa.PublicKey, but got pub key type %T", pubKey)
	}
	return VerifySignature(rsaKey, digest, sig)
}
