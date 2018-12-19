package pgpcli

import (
	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
)

const (
	// Type of this signer is "pgpcli" represents a signer that
	// shells out to gpg2 to sign artifacts since the golang "pgp"
	// signer doesn't support signing with subkeys
	// https://godoc.org/golang.org/x/crypto/openpgp#ArmoredDetachSign
	// or loading keys exported with gnu-dummy s2k encrypted
	// passphrases https://github.com/golang/go/issues/13605
	Type = "pgpcli"
)

// PGPCLISigner holds the configuration of the signer
type PGPCLISigner struct {
	signer.Configuration

	// KeyID is the fingerprint of the gpg key or subkey to use
	// e.g. 0xA2B637F535A86009
	KeyID string

	// Passphrase is the optional passphrase to use decrypt the
	// gpg secret key
	Passphrase string
}

// New initializes a pgp signer using a configuration
func New(conf signer.Configuration) (s *PGPCLISigner, err error) {
	s = new(PGPCLISigner)

	if conf.Type != Type {
		return nil, errors.Errorf("pgpcli: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, errors.New("pgpcli: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	if conf.PrivateKey == "" {
		return nil, errors.New("pgpcli: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey

	if conf.KeyID == "" {
		return nil, errors.New("pgpcli: missing gpg key ID in signer configuration")
	}
	s.KeyID = conf.KeyID

	s.Passphrase = conf.Passphrase
	return
}

// Config returns the configuration of the current signer
func (s *PGPCLISigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
	}
}

// SignData takes data and returns an armored signature with pgp header and footer
func (s *PGPCLISigner) SignData(data []byte, options interface{}) (signer.Signature, error) {
	sig := new(Signature)
	return sig, nil
}

// Signature is a PGP signature
type Signature struct {
	Data []byte
}

// Marshal doesn't do much for this signer. sig.Data already contains
// an armored signature, so we simply convert it to a string and return it
func (sig *Signature) Marshal() (string, error) {
	return string(sig.Data), nil
}

// Unmarshal also does very little. It simply converts the armored signature
// from a string to an []byte, but doesn't attempt to parse it, and returns it
// as a Signature
func Unmarshal(sigstr string) (signer.Signature, error) {
	sig := new(Signature)
	sig.Data = []byte(sigstr)
	return sig, nil
}

// Options are not implemented for this signer
type Options struct {
}

// GetDefaultOptions returns default options of the signer
func (s *PGPCLISigner) GetDefaultOptions() interface{} {
	return Options{}
}
