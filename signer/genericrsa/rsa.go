package genericrsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"hash"
	"io"

	"go.mozilla.org/autograph/formats"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
)

const (
	// Type of this signer is "genericrsa"
	Type = "genericrsa"
)

// RSASigner holds the configuration of the signer
type RSASigner struct {
	signer.Configuration

	// key is the RSA private key to sign hashes.
	// we use the `crypto.PrivateKey` interface to support
	// keys in HSM.
	key crypto.PrivateKey

	// pubkey is an RSA Public Key
	pubKey crypto.PublicKey

	// rng is our random number generator
	rng io.Reader

	// sigOpts stores options for PSS signing and is nil
	// in pkcs15 mode
	sigOpts crypto.SignerOpts

	// hashSize is the byte size of the configured hash checksum
	hashSize int
}

const (
	// ModePSS enables PSS padding mode
	ModePSS = "pss"

	// ModePKCS15 enables PKCS15 padding mode
	ModePKCS15 = "pkcs15"
)

// Options contains options for creating and verifying PKCS15 signatures.
type Options struct {
	// Hash, if not zero, overrides the hash function passed to SignPSS.
	// This is the only way to specify the hash function when using the
	// crypto.Signer interface.
	Hash crypto.Hash
}

// HashFunc returns the Hash used by the signer so that Options implements
// crypto.SignerOpts
func (opts *Options) HashFunc() crypto.Hash {
	return opts.Hash

}

// New initializes a rsa signer using a configuration
func New(conf signer.Configuration) (s *RSASigner, err error) {
	s = new(RSASigner)

	if conf.Type != Type {
		return nil, errors.Errorf("genericrsa: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, errors.New("genericrsa: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	switch conf.Mode {
	case ModePSS, ModePKCS15:
		s.Mode = conf.Mode
	case "":
		return nil, errors.Errorf("genericrsa: missing signer mode for signer %q, must be 'pkcs15' or 'pss'", s.ID)
	default:
		return nil, errors.Errorf("genericrsa: invalid signer mode %q for signer %q, must be 'pkcs15' or 'pss'", conf.Mode, s.ID)
	}

	if conf.PrivateKey == "" {
		return nil, errors.Errorf("genericrsa: missing private key for signer %q", s.ID)
	}
	s.PrivateKey = conf.PrivateKey

	if conf.PublicKey == "" {
		return nil, errors.Errorf("genericrsa: missing public key for signer %q", s.ID)
	}
	s.rng = conf.GetRand()
	s.key, s.pubKey, s.PublicKey, err = conf.GetKeys()
	if err != nil {
		return nil, errors.Wrapf(err, "genericrsa: error fetching key for signer %q", s.ID)
	}
	_, ok := s.pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("genericrsa: unsupported public key type %T for signer %q, use RSA keys", s.pubKey, s.ID)
	}

	s.Hash = conf.Hash
	var hashID crypto.Hash
	switch s.Hash {
	case "sha1":
		hashID = crypto.SHA1
		s.hashSize = sha1.Size
	case "sha256":
		hashID = crypto.SHA256
		s.hashSize = sha256.Size
	default:
		return nil, errors.Errorf("genericrsa: unsupported hash %q for signer %q, must be 'sha1' or 'sha256'", s.Hash, s.ID)
	}

	s.SaltLength = conf.SaltLength
	switch s.Mode {
	case ModePSS:
		s.sigOpts = &rsa.PSSOptions{
			SaltLength: s.SaltLength,
			Hash:       hashID,
		}
	case ModePKCS15:
		if s.SaltLength != 0 {
			return nil, errors.Errorf("genericrsa: signer %q uses mode %q and sets salt length to %d, which is only valid in 'pss' mode", s.ID, s.Mode, s.SaltLength)
		}
		s.sigOpts = &Options{
			Hash: hashID,
		}
	}
	return s, nil
}

// Config returns the configuration of the current signer
func (s *RSASigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		Mode:       s.Mode,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
		SignerOpts: s.sigOpts,
	}
}

// SignData takes data, hashes it and returns a signed base64 encoded hash
func (s *RSASigner) SignData(data []byte, options interface{}) (signer.Signature, error) {
	var h hash.Hash
	switch s.Hash {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	}
	h.Write(data)
	return s.SignHash(h.Sum(nil), options)
}

// SignHash takes an input hash and returns a signed base64 encoded hash
func (s *RSASigner) SignHash(digest []byte, options interface{}) (signer.Signature, error) {
	if len(digest) != s.hashSize {
		return nil, errors.Errorf("genericrsa: refusing to sign input hash. Got length %d, expected %d", len(digest), s.hashSize)
	}
	sigBytes, err := s.key.(crypto.Signer).Sign(s.rng, digest, s.sigOpts)
	if err != nil {
		return nil, errors.Wrap(err, "genericrsa: error signing hash")
	}
	sig := new(Signature)
	sig.Data = sigBytes
	return sig, nil
}

// Signature is a rsa signature
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

// GetDefaultOptions returns default options of the signer
func (s *RSASigner) GetDefaultOptions() interface{} {
	return Options{}
}

// VerifySignature verifies a rsa signature for the given SHA1
// digest for the given RSA public and signature bytes
func VerifySignature(input, sigBytes []byte, pubKey *rsa.PublicKey, sigopt interface{}, mode string) (err error) {
	switch mode {
	case ModePSS:
		// in PSS mode, the signer options are unmarshalled into
		// a rsa.PSSOptions struct that contains the salt length
		// and the hash algorithm used for signing
		var opt rsa.PSSOptions
		marshalledOpt, err := json.Marshal(sigopt)
		if err != nil {
			return err
		}
		err = json.Unmarshal(marshalledOpt, &opt)
		if err != nil {
			return err
		}
		h := opt.Hash.New()
		h.Write(input)
		hashed := h.Sum(nil)
		return rsa.VerifyPSS(pubKey, opt.Hash, hashed, sigBytes, &opt)
	case ModePKCS15:
		// in PKCS15 mode, the signer options are unmarshalled into
		// an option struct that only contains the hash used for signing
		marshalledOpt, err := json.Marshal(sigopt)
		if err != nil {
			return err
		}
		var opt Options
		err = json.Unmarshal(marshalledOpt, &opt)
		if err != nil {
			return err
		}
		h := opt.Hash.New()
		h.Write(input)
		hashed := h.Sum(nil)
		return rsa.VerifyPKCS1v15(pubKey, opt.Hash, hashed, sigBytes)
	default:
		return errors.Errorf("genericrsa: invalid mode %q", mode)
	}
}

// VerifyGenericRsaSignatureResponse is a helper that takes
// an input and autograph signature response and verify its signature.
func VerifyGenericRsaSignatureResponse(input []byte, sr formats.SignatureResponse) error {
	if sr.Type != Type {
		return errors.Errorf("genericrsa: signature response of type %q cannot be verified by %q", sr.Type, Type)
	}
	sig, err := Unmarshal(sr.Signature)
	if err != nil {
		return errors.Wrap(err, "genericrsa: failed to unmarshal rsa signature")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(sr.PublicKey)
	if err != nil {
		return errors.Wrap(err, "genericrsa: failed to decode public key")
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return errors.Wrap(err, "genericrsa: failed to parse pkix public key")
	}
	pubKey := keyInterface.(*rsa.PublicKey)
	err = VerifySignature(input, sig.(*Signature).Data, pubKey, sr.SignerOpts, sr.Mode)
	if err != nil {
		return errors.Wrap(err, "genericrsa: failed to verify signature")
	}
	return nil
}
