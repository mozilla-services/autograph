package mar

import (
	"crypto"
	"crypto/rsa"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/mar"
)

const (
	Type = "mar"
)

type MARSigner struct {
	signer.Configuration
	signingKey crypto.PrivateKey
}

// New initializes a mar signer using a configuration
func New(conf signer.Configuration) (s *MARSigner, err error) {
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

func (s *MARSigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	var marFile mar.File
	err := mar.Unmarshal(input, &marFile)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to unmarshal input file")
	}

	// flush the signatures if any is present, we'll make new ones
	marFile.SignaturesHeader.NumSignatures = uint32(0)
	marFile.Signatures = nil

	marFile.PrepareSignature(s.signingKey.(*rsa.PrivateKey))
	err = marFile.FinalizeSignatures()
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to finalize signature")
	}

	// write out the MAR file
	output, err := marFile.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to marshal signed file")
	}
	return output, nil
}

func (s *MARSigner) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	return nil, nil
}

// Options is empty for this signer type
type Options struct{}

// GetDefaultOptions returns default options of the signer
func (s *MARSigner) GetDefaultOptions() interface{} {
	return Options{}
}
