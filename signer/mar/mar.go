package mar

import (
	"crypto"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
)

const (
	Type = "mar"
)

type MARSigner struct {
	signer.Configuration
	signingKey crypto.PrivateKey
}

// New initializes a mar signer using a configuration
func New(conf signer.Configuration) (s *APKSigner, err error) {
	s = new(MARSigner)
	if conf.Type != Type {
		return nil, errors.Errorf("mar: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type
	if conf.ID == "" {
		return nil, errors.New("mar: missing signer ID in signer configuration")
	}
	s.ID = conf.ID
	if conf.PrivateKey == "" {
		return nil, errors.New("mar: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	s.signingKey, err = signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to parse private key")
	}
	return
}

// Config returns the configuration of the current signer
func (s *MARSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
	}
}

func (s *APKSigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	// make MAR hash
	signableBlock, err := makeMARSignableBlock(input)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to make MAR signable block")
	}
	// sign hash

	// pack signature in mar
	err := packSignatureInMar
	return
}

func (s *APKSigner) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	return
}

func (sig *Signature) Verify() error {
	return
}

// Signature is a RSA PKCS1 signature
type Signature struct {
	Data     []byte
	Finished bool
}

// Options is empty for this signer type
type Options struct{}

// GetDefaultOptions returns default options of the signer
func (s *MARSigner) GetDefaultOptions() interface{} {
	return Options{}
}
