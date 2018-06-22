package mar

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// VerifySignature takes a signed block, a signature, an algorithm id and a public key and returns
// nil if the signature verifies, or an error if it does not
func VerifySignature(input []byte, signature []byte, sigalg uint32, key crypto.PublicKey) error {
	digest, hashAlg, err := Hash(input, sigalg)
	if err != nil {
		return err
	}
	return VerifyHashSignature(signature, digest, hashAlg, key)
}

// VerifyHashSignature takes a signature, the digest of a signed MAR block, a hash algorithm and a public
// key and returns nil if a valid signature is found, or an error if it isn't
func VerifyHashSignature(signature []byte, digest []byte, hashAlg crypto.Hash, key crypto.PublicKey) error {
	switch key.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), hashAlg, digest, signature)
		if err == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		r, s := new(big.Int), new(big.Int)
		r.SetBytes(signature[:len(signature)/2])
		s.SetBytes(signature[len(signature)/2:])
		if ecdsa.Verify(key.(*ecdsa.PublicKey), digest, r, s) {
			return nil
		}
	default:
		return fmt.Errorf("unknown public key type %T", key)
	}
	return fmt.Errorf("invalid signature")
}

// VerifySignature attempts to verify signatures in the MAR file using
// the provided public key until one of them passes. A valid signature
// is indicated by returning a nil error.
func (file *File) VerifySignature(key crypto.PublicKey) error {
	signedBlock, err := file.MarshalForSignature()
	if err != nil {
		return err
	}
	for _, sig := range file.Signatures {
		err = VerifySignature(signedBlock, sig.Data, sig.AlgorithmID, key)
		if err == nil {
			debugPrint("found valid %s signature\n", sig.Algorithm)
			return nil
		}
	}
	return fmt.Errorf("no valid signature found")
}

// VerifyWithFirefoxKeys checks each signature in the MAR file against the list of known
// Firefox signing keys, and returns isSigned = true if at least one signature
// validates against a known key. It also returns the names of the signing keys
// in an []string
func (file *File) VerifyWithFirefoxKeys() (keys []string, isSigned bool, err error) {
	isSigned = false
	for keyName, keyPem := range FirefoxReleasePublicKeys {
		block, _ := pem.Decode([]byte(keyPem))
		if block == nil {
			err = fmt.Errorf("failed to parse PEM block of key %q", keyName)
			return nil, false, err
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			err = fmt.Errorf("failed to parse DER block of key %q: %v", keyName, err)
			return nil, false, err
		}
		err = file.VerifySignature(pub)
		if err == nil {
			// signature is valid
			keys = append(keys, keyName)
			isSigned = true
		} else {
			debugPrint("signature verification failed with firefox key %q\n", keyName)
		}
	}
	return
}
