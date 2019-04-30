package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"github.com/pkg/errors"
	"io"
	"math/big"
)

// ContextSignature identifies the context of the signature as a
// COSE_Signature structure per
// https://tools.ietf.org/html/rfc8152#section-4.4
const ContextSignature = "Signature"

// Supported Algorithms
var (
	// PS256 is RSASSA-PSS w/ SHA-256 from [RFC8230]
	PS256 = getAlgByNameOrPanic("PS256")

	// ES256 is ECDSA w/ SHA-256 from [RFC8152]
	ES256 = getAlgByNameOrPanic("ES256")

	// ES384 is ECDSA w/ SHA-384 from [RFC8152]
	ES384 = getAlgByNameOrPanic("ES384")

	// ES512 is ECDSA w/ SHA-512 from [RFC8152]
	ES512 = getAlgByNameOrPanic("ES512")
)

// ByteSigner take a signature digest and returns COSE signature bytes
type ByteSigner interface {
	// Sign returns the COSE signature as a byte slice
	Sign(rand io.Reader, digest []byte) (signature []byte, err error)
}

// ByteVerifier checks COSE signatures
type ByteVerifier interface {
	// Verify returns nil for a successfully verified signature or an error
	Verify(digest []byte, signature []byte) (err error)
}

// Signer holds a COSE Algorithm and private key for signing messages
type Signer struct {
	PrivateKey crypto.PrivateKey
	alg        *Algorithm
}

// RSAOptions are options for NewSigner currently just the RSA Key
// size
type RSAOptions struct {
	Size int
}

// NewSigner returns a Signer with a generated key
func NewSigner(alg *Algorithm, options interface{}) (signer *Signer, err error) {
	var privateKey crypto.PrivateKey

	if alg.privateKeyType == KeyTypeECDSA {
		if alg.privateKeyECDSACurve == nil {
			err = errors.Errorf("No ECDSA curve found for algorithm")
			return nil, err
		}

		privateKey, err = ecdsa.GenerateKey(alg.privateKeyECDSACurve, rand.Reader)
		if err != nil {
			err = errors.Wrapf(err, "error generating ecdsa signer private key")
			return nil, err
		}
	} else if alg.privateKeyType == KeyTypeRSA {
		var keyBitLen int = alg.minRSAKeyBitLen

		if opts, ok := options.(RSAOptions); ok {
			if opts.Size > alg.minRSAKeyBitLen {
				keyBitLen = opts.Size
			} else {
				err = errors.Errorf("error generating rsa signer private key RSA key size must be at least %d", alg.minRSAKeyBitLen)
				return nil, err
			}
		}
		privateKey, err = rsa.GenerateKey(rand.Reader, keyBitLen)
		if err != nil {
			err = errors.Wrapf(err, "error generating rsa signer private key")
			return nil, err
		}
	} else {
		return nil, ErrUnknownPrivateKeyType
	}

	return &Signer{
		PrivateKey: privateKey,
		alg:        alg,
	}, nil
}

// NewSignerFromKey checks whether the privateKey is supported and
// returns a Signer using the provided key
func NewSignerFromKey(alg *Algorithm, privateKey crypto.PrivateKey) (signer *Signer, err error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	case *ecdsa.PrivateKey:
	default:
		return nil, ErrUnknownPrivateKeyType
	}
	return &Signer{
		PrivateKey: privateKey,
		alg:        alg,
	}, nil
}

// Public returns the crypto.PublicKey for the Signer's privateKey
func (s *Signer) Public() (publicKey crypto.PublicKey) {
	switch key := s.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return key.Public()
	case *ecdsa.PrivateKey:
		return key.Public()
	default:
		panic("Could not return public key for Unrecognized private key type.")
	}
}

// Sign returns the COSE signature as a byte slice
func (s *Signer) Sign(rand io.Reader, digest []byte) (signature []byte, err error) {
	switch key := s.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if s.alg.privateKeyType != KeyTypeRSA {
			return nil, errors.Errorf("Key type must be RSA")
		}
		if key.N.BitLen() < s.alg.minRSAKeyBitLen {
			return nil, errors.Errorf("RSA key must be at least %d bits long", s.alg.minRSAKeyBitLen)
		}

		sig, err := rsa.SignPSS(rand, key, s.alg.HashFunc, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       s.alg.HashFunc,
		})
		if err != nil {
			return nil, errors.Errorf("rsa.SignPSS error %s", err)
		}
		return sig, nil
	case *ecdsa.PrivateKey:
		if s.alg.privateKeyType != KeyTypeECDSA {
			return nil, errors.Errorf("Key type must be ECDSA")
		}

		// https://tools.ietf.org/html/rfc8152#section-8.1
		r, s, err := ecdsa.Sign(rand, key, digest)
		if err != nil {
			return nil, errors.Errorf("ecdsa.Sign error %s", err)
		}

		// These integers (r and s) will be the same length as
		// the length of the key used for the signature
		// process.
		const tolerance = uint(1)
		rByteLen, sByteLen, dByteLen := len(s.Bits()), len(r.Bits()), len(key.D.Bits())
		if !(approxEqual(sByteLen, rByteLen, tolerance) && approxEqual(sByteLen, dByteLen, tolerance) && approxEqual(dByteLen, rByteLen, tolerance)) {
			return nil, errors.Errorf("Byte lengths of integers r and s (%d and %d) do not match the key length %d±%d\n", sByteLen, rByteLen, dByteLen, tolerance)
		}

		// The signature is encoded by converting the integers
		// into byte strings of the same length as the key
		// size.  The length is rounded up to the nearest byte
		// and is left padded with zero bits to get to the
		// correct length.  The two integers are then
		// concatenated together to form a byte string that is
		// the resulting signature.
		n := ecdsaCurveKeyBytesSize(key.Curve)
		sig := make([]byte, 0)
		sig = append(sig, I2OSP(r, n)...)
		sig = append(sig, I2OSP(s, n)...)

		return sig, nil
	default:
		return nil, ErrUnknownPrivateKeyType
	}
}

// Verifier returns a Verifier using the Signer's public key and
// Algorithm
func (s *Signer) Verifier() (verifier *Verifier) {
	return &Verifier{
		PublicKey: s.Public(),
		Alg:       s.alg,
	}
}

// Verifier holds a PublicKey and Algorithm to verify signatures
type Verifier struct {
	PublicKey crypto.PublicKey
	Alg       *Algorithm
}

// Verify verifies a signature returning nil for success or an error
func (v *Verifier) Verify(digest []byte, signature []byte) (err error) {
	if v.Alg.Value > -1 { // Negative numbers are used for second layer objects (COSE_Signature and COSE_recipient)
		return ErrInvalidAlg
	}

	switch key := v.PublicKey.(type) {
	case *rsa.PublicKey:
		hashFunc := v.Alg.HashFunc

		err = rsa.VerifyPSS(key, hashFunc, digest, signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashFunc,
		})
		if err != nil {
			return errors.Errorf("verification failed rsa.VerifyPSS err %s", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if v.Alg.privateKeyECDSACurve == nil {
			return errors.Errorf("Could not find an elliptic curve for the ecdsa algorithm")
		}

		algCurveBitSize := v.Alg.privateKeyECDSACurve.Params().BitSize
		keyCurveBitSize := key.Curve.Params().BitSize

		if algCurveBitSize != keyCurveBitSize {
			return errors.Errorf("Expected %d bit key, got %d bits instead", algCurveBitSize, keyCurveBitSize)
		}

		algKeyBytesSize := ecdsaCurveKeyBytesSize(v.Alg.privateKeyECDSACurve)

		// signature bytes is the keys with padding r and s
		if len(signature) != 2*algKeyBytesSize {
			return errors.Errorf("invalid signature length: %d", len(signature))
		}

		r := big.NewInt(0).SetBytes(signature[:algKeyBytesSize])
		s := big.NewInt(0).SetBytes(signature[algKeyBytesSize:])

		ok := ecdsa.Verify(key, digest, r, s)
		if ok {
			return nil
		}
		return ErrECDSAVerification
	default:
		return ErrUnknownPublicKeyType
	}
}

// buildAndMarshalSigStructure creates a Sig_structure, populates it
// with the appropriate fields, and marshals it to CBOR bytes
func buildAndMarshalSigStructure(bodyProtected, signProtected, external, payload []byte) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sigStructure := []interface{}{
		ContextSignature,
		bodyProtected, // message.headers.EncodeProtected(),
		signProtected, // message.signatures[0].headers.EncodeProtected(),
		external,
		payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = Marshal(sigStructure)
	if err != nil {
		return nil, errors.Errorf("Error marshaling Sig_structure: %s", err)
	}
	return ToBeSigned, nil
}

// hashSigStructure computes the crypto.Hash digest of a byte slice
func hashSigStructure(ToBeSigned []byte, hash crypto.Hash) (digest []byte, err error) {
	if !hash.Available() {
		return []byte(""), ErrUnavailableHashFunc
	}
	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned) // Write() on hash never fails
	digest = hasher.Sum(nil)
	return digest, nil
}

// ecdsaCurveKeyBytesSize returns the ECDSA key size in bytes with padding
func ecdsaCurveKeyBytesSize(curve elliptic.Curve) (keyBytesSize int) {
	curveBits := curve.Params().BitSize
	keyBytesSize = curveBits / 8

	// add a byte of padding for curves like P521
	if curveBits%8 > 0 {
		keyBytesSize++
	}
	return
}

// I2OSP "Integer-to-Octet-String" converts a nonnegative integer to
// an octet string of a specified length
//
// https://tools.ietf.org/html/rfc8017#section-4.1
func I2OSP(b *big.Int, n int) []byte {
	var (
		octetString     = b.Bytes()
		octetStringSize = len(octetString)
		result          = make([]byte, n)
	)
	if !(b.Sign() == 0 || b.Sign() == 1) {
		panic("I2OSP error: integer must be zero or positive")
	}
	if n == 0 || octetStringSize > n {
		panic("I2OSP error: integer too large")
	}

	subtle.ConstantTimeCopy(1, result[:n-octetStringSize], result[:n-octetStringSize])
	subtle.ConstantTimeCopy(1, result[n-octetStringSize:], octetString)
	return result
}

// FromBase64Int decodes a base64-encoded string into a big.Int or panics
//
// from https://github.com/square/go-jose/blob/789a4c4bd4c118f7564954f441b29c153ccd6a96/utils_test.go#L45
// Apache License 2.0
func FromBase64Int(data string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		panic("Invalid test data")
	}
	return new(big.Int).SetBytes(val)
}

// Sign returns the SignatureBytes for each Signer in the same order
// on the digest or the error from the first failing Signer
func Sign(rand io.Reader, digest []byte, signers []ByteSigner) (signatures [][]byte, err error) {
	var signatureBytes []byte

	for _, signer := range signers {
		signatureBytes, err = signer.Sign(rand, digest)
		if err != nil {
			return
		}
		signatures = append(signatures, signatureBytes)
	}
	return
}

// Verify returns nil if all Verifier verify the SignatureBytes or the
// error from the first failing Verifier
func Verify(digest []byte, signatures [][]byte, verifiers []ByteVerifier) (err error) {
	if len(signatures) != len(verifiers) {
		return errors.Errorf("Wrong number of signatures %d and verifiers %d", len(signatures), len(verifiers))
	}
	for i, verifier := range verifiers {
		err = verifier.Verify(digest, signatures[i])
		if err != nil {
			return
		}
	}
	return nil
}

// approxEquals returns a bool of whether x and y are equal to within
// a given tolerance
func approxEqual(x, y int, tolerance uint) bool {
	var (
		larger, smaller int
	)
	if x > y {
		larger = x
		smaller = y
	} else {
		larger = y
		smaller = x
	}
	return uint(larger-smaller) <= tolerance
}
