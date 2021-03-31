package mar

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/mozilla-services/autograph/signer"
	"github.com/pkg/errors"
	margo "go.mozilla.org/mar"
)

const (
	// Type of this signer is "mar"
	Type = "mar"
)

// MARSigner holds the configuration of the signer
type MARSigner struct {
	signer.Configuration
	signingKey    crypto.PrivateKey
	publicKey     crypto.PublicKey
	rand          io.Reader
	defaultSigAlg uint32
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
	s.rand = conf.GetRand()
	s.signingKey, s.publicKey, s.PublicKey, err = conf.GetKeys()
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to get keys")
	}

	// select the default signature algorithm depending on the public key type
	switch pubKey := s.publicKey.(type) {
	case *rsa.PublicKey:
		s.defaultSigAlg = margo.SigAlgRsaPkcs1Sha384
	case *ecdsa.PublicKey:
		switch pubKey.Params().Name {
		case elliptic.P256().Params().Name:
			s.defaultSigAlg = margo.SigAlgEcdsaP256Sha256
		case elliptic.P384().Params().Name:
			s.defaultSigAlg = margo.SigAlgEcdsaP384Sha384
		default:
			return nil, fmt.Errorf("mar: elliptic curve %q is not supported", pubKey.Params().Name)
		}
	default:
		return nil, errors.Errorf("mar: unsupported public key type %T", s.signingKey)
	}
	return
}

// Config returns the configuration of the current signer
func (s *MARSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
	}
}

// SignFile takes a MAR file and returns a signed MAR file
func (s *MARSigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	var marFile margo.File
	err := margo.Unmarshal(input, &marFile)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to unmarshal input file")
	}

	// flush the signatures if any is present, we'll make new ones
	marFile.SignaturesHeader.NumSignatures = uint32(0)
	marFile.Signatures = nil
	err = marFile.PrepareSignature(s.signingKey, s.publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to prepare signature")
	}
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

// SignData takes a MAR file already marshalled for signature and returns a base64 encoded signature.
//
// This function expects the caller to handle parsing of the MAR file, which can be really tricky
// because the signature headers need to be placed in the file prior to marshalling it for
// signature. You should consider calling the SignFile interface instead, which will handle
// all that magic for you.
func (s *MARSigner) SignData(data []byte, options interface{}) (signer.Signature, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to get options")
	}
	// if no options were defined, use the default value from the signer
	if opt.SigAlg == 0 {
		opt.SigAlg = s.defaultSigAlg
	}
	hashed, _, err := margo.Hash(data, opt.SigAlg)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to hash input")
	}
	return s.SignHash(hashed, options)
}

// SignHash takes the hash of the signable data of a MAR file, signs it and returns a base64 encoded signature
func (s *MARSigner) SignHash(hashed []byte, options interface{}) (signer.Signature, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to get options")
	}
	// if no options were defined, use the default value from the signer
	if opt.SigAlg == 0 {
		opt.SigAlg = s.defaultSigAlg
	}
	sig := new(Signature)
	sig.Data, err = margo.Sign(s.signingKey, s.rand, hashed, opt.SigAlg)
	if err != nil {
		return nil, errors.Wrap(err, "mar: failed to sign")
	}
	return sig, nil
}

// Signature is a MAR signature
type Signature struct {
	Data []byte
}

// Marshal returns the base64 representation of a signature
func (sig *Signature) Marshal() (string, error) {
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Options accepts the name of the signature algorithm used by the SignData
// interface to decide which algorithm to sign the data with
type Options struct {
	// SigAlg is an integer that represents the type of signature requested.
	// It must map the SigAlg constants from the MAR package
	SigAlg uint32 `json:"sigalg"`
}

// GetDefaultOptions returns default options of the signer
func (s *MARSigner) GetDefaultOptions() interface{} {
	return Options{SigAlg: s.defaultSigAlg}
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
