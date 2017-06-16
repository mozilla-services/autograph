package contentsignature // import "go.mozilla.org/autograph/signer/contentsignature"

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"hash"

	"go.mozilla.org/autograph/signer"

	"github.com/pkg/errors"
)

const (
	// Type of this signer is 'contentsignature'
	Type = "contentsignature"

	// P256ECDSA defines an ecdsa content signature on the P-256 curve
	P256ECDSA = "p256ecdsa"

	// P384ECDSA defines an ecdsa content signature on the P-384 curve
	P384ECDSA = "p384ecdsa"

	// P521ECDSA defines an ecdsa content signature on the P-521 curve
	P521ECDSA = "p521ecdsa"

	// SignaturePrefix is a string preprended to data prior to signing
	SignaturePrefix = "Content-Signature:\x00"
)

// ContentSigner implements an issuer of content signatures
type ContentSigner struct {
	signer.Configuration
	privKey *ecdsa.PrivateKey
}

// New initializes a ContentSigner using a signer configuration
func New(conf signer.Configuration) (s *ContentSigner, err error) {
	s = new(ContentSigner)
	s.ID = conf.ID
	s.Type = conf.Type
	s.PrivateKey = conf.PrivateKey
	s.X5U = conf.X5U
	if conf.Type != Type {
		return nil, errors.Errorf("contentsignature: invalid type %q, must be %q", conf.Type, Type)
	}
	if conf.ID == "" {
		return nil, errors.New("contentsignature: missing signer ID in signer configuration")
	}
	if conf.PrivateKey == "" {
		return nil, errors.New("contentsignature: missing private key in signer configuration")
	}
	privKey, err := signer.ParsePrivateKey([]byte(conf.PrivateKey))
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature: failed to parse private key")
	}
	switch privKey.(type) {
	case *ecdsa.PrivateKey:
		s.privKey = privKey.(*ecdsa.PrivateKey)
	default:
		return nil, errors.Errorf("contentsignature: invalid private key algorithm, must be ecdsa, not %T", s.privKey)
	}
	pubkeybytes, err := x509.MarshalPKIXPublicKey(s.privKey.Public())
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature: failed to unmarshal public key")
	}
	s.PublicKey = base64.StdEncoding.EncodeToString(pubkeybytes)
	return
}

// Config returns the configuration of the current signer
func (s *ContentSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
		X5U:        s.X5U,
	}
}

// SignData takes input data, templates it, hashes it and signs it.
// The returned signature is of type ContentSignature and ready to be Marshalled.
func (s *ContentSigner) SignData(input []byte, options interface{}) (signer.Signature, error) {
	if len(input) < 10 {
		return nil, errors.Errorf("contentsignature: refusing to sign input data shorter than 10 bytes")
	}
	alg, hash := makeTemplatedHash(input, s.CurveName())
	sig, err := s.SignHash(hash, options)
	sig.(*ContentSignature).storeHashName(alg)
	return sig, err
}

// hash returns the templated sha384 of the input data. The template adds
// the string "Content-Signature:\x00" before the input data prior to
// calculating the sha384.
//
// The name of the hash function is returned, followed by the hash bytes
func makeTemplatedHash(data []byte, curvename string) (alg string, out []byte) {
	templated := make([]byte, len(SignaturePrefix)+len(data))
	copy(templated[:len(SignaturePrefix)], []byte(SignaturePrefix))
	copy(templated[len(SignaturePrefix):], data)
	var md hash.Hash
	switch curvename {
	case P384ECDSA:
		md = sha512.New384()
		alg = "sha384"
	case P521ECDSA:
		md = sha512.New()
		alg = "sha512"
	default:
		md = sha256.New()
		alg = "sha256"
	}
	md.Write(templated)
	return alg, md.Sum(nil)
}

// SignHash takes an input hash and returns a signature. It assumes the input data
// has already been hashed with something like sha384
func (s *ContentSigner) SignHash(input []byte, options interface{}) (signer.Signature, error) {
	if len(input) != 32 && len(input) != 48 && len(input) != 64 {
		return nil, errors.Errorf("contentsignature: refusing to sign input hash. length %d, expected 32, 48 or 64", len(input))
	}
	var err error
	csig := new(ContentSignature)
	csig.Len = getSignatureLen(s.privKey.Params().BitSize)
	csig.CurveName = s.CurveName()
	csig.X5U = s.X5U
	csig.ID = s.ID
	csig.R, csig.S, err = ecdsa.Sign(rand.Reader, s.privKey, input)
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature: failed to sign hash")
	}
	csig.Finished = true
	return csig, nil
}

// getSignatureLen returns the size of an ECDSA signature issued by the signer.
// The signature length is double the size size of the curve field, in bytes
// (each R and S value is equal to the size of the curve field).
// If the curve field it not a multiple of 8, round to the upper multiple of 8.
func getSignatureLen(bitsize int) int {
	siglen := 0
	if bitsize%8 != 0 {
		siglen = 8 - (bitsize % 8)
	}
	siglen += bitsize
	siglen /= 8
	siglen *= 2
	return siglen
}

// CurveName returns an elliptic curve string identifier, or an empty string
// if the curve is unknown
func (s *ContentSigner) CurveName() string {
	switch s.privKey.Curve.Params().Name {
	case "P-256":
		return P256ECDSA
	case "P-384":
		return P384ECDSA
	case "P-521":
		return P521ECDSA
	default:
		return ""
	}
}

// GetDefaultOptions returns nil because this signer has no option
func (s *ContentSigner) GetDefaultOptions() interface{} {
	return nil
}
