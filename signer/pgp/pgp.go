package pgp

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/mozilla-services/autograph/signer"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

const (
	// Type of this signer is "pgp", which represents a signer
	// that uses the native golang.org/x/crypto/openpgp to sign
	// data
	Type = "pgp"
)

// PGPSigner holds the configuration of the signer
type PGPSigner struct {
	signer.Configuration
	entity *openpgp.Entity
}

// New initializes a pgp signer using a configuration
func New(conf signer.Configuration) (s *PGPSigner, err error) {
	s = new(PGPSigner)

	if conf.Type != Type {
		return nil, errors.Errorf("pgp: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, errors.New("pgp: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	if conf.PrivateKey == "" {
		return nil, errors.New("pgp: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(s.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "pgp: failed to read armored keyring")
	}
	if len(entities) != 1 {
		return nil, errors.Errorf("pgp: found %d entities in armored keyring, expected one", len(entities))
	}
	s.entity = entities[0]

	// serialize the public key
	var pubkeybuf bytes.Buffer
	err = s.entity.Serialize(&pubkeybuf)
	if err != nil {
		return nil, errors.Wrap(err, "pgp: failed to serialize public key")
	}
	armoredbuf := bytes.NewBuffer(nil)
	ewrbuf, err := armor.Encode(armoredbuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, errors.Wrap(err, "pgp: failed to serialize public key")
	}
	_, err = ewrbuf.Write(pubkeybuf.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "pgp: failed to serialize public key")
	}
	ewrbuf.Close()
	s.PublicKey = armoredbuf.String()

	return
}

// Config returns the configuration of the current signer
func (s *PGPSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
	}
}

// SignData takes data and returns an armored signature with pgp header and footer
func (s *PGPSigner) SignData(data []byte, options interface{}) (signer.Signature, error) {
	out := bytes.NewBuffer(nil)
	message := bytes.NewBuffer(data)
	err := openpgp.ArmoredDetachSign(out, s.entity, message, nil)
	if err != nil {
		return nil, errors.Wrap(err, "pgp: failed to sign")
	}
	sig := new(Signature)
	sig.Data = out.Bytes()
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
func (s *PGPSigner) GetDefaultOptions() interface{} {
	return Options{}
}
