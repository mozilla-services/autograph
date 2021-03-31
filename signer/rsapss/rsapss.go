package rsapss

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/mozilla-services/autograph/signer"
)

const (
	// Type of this signer is "rsapss"
	Type = "rsapss"
)

// RSAPSSSigner holds the configuration of the signer
type RSAPSSSigner struct {
	signer.Configuration

	// key is the RSA private key to sign hashes.
	// we use the `crypto.PrivateKey` interface to support
	// keys in HSM.
	key crypto.PrivateKey

	// pubkey is an RSA Public Key
	pubKey crypto.PublicKey

	// rng is our random number generator
	rng io.Reader
}

// New initializes a rsapss signer using a configuration
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

	if conf.PrivateKey == "" {
		return nil, errors.New("rsapss: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey

	if conf.PublicKey == "" {
		return nil, errors.New("rsapss: missing public key in signer configuration")
	}
	s.rng = conf.GetRand()
	s.key, s.pubKey, s.PublicKey, err = conf.GetKeys()
	if err != nil {
		return nil, errors.Wrapf(err, "rsapss: error fetching key from signer configuration")
	}
	_, ok := s.pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("rsapss: unsupported public key type %T, use RSA keys", s.pubKey)
	}
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

// SignData takes data, hashes it and returns a signed base64 encoded hash
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

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA1,
	}

	sigBytes, err := s.key.(crypto.Signer).Sign(s.rng, digest, opts)
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

// Unmarshal decodes a base64 signature string into a Signature
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
	err := rsa.VerifyPSS(pubKey, crypto.SHA1, digest, sigBytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA1,
	})
	return errors.Wrapf(err, "rsapss: failed to verify signature")
}

// VerifySignatureFromB64 verifies a signature from base64 encoded
// digest, signature, and public key as autograph returns from its API
// used in the client and monitor
func VerifySignatureFromB64(b64Digest, b64Signature, b64PubKey string) error {
	digest, err := base64.StdEncoding.DecodeString(b64Digest)
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
	pubKey, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return err
	}
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("expected rsa.PublicKey, but got pub key type %T", pubKey)
	}
	return VerifySignature(rsaKey, digest, sig)
}
