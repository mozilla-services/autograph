// Package contentsignature provides a type, marshal/unmarshaller, and
// verifier for the Firefox content signing scheme.
//
// It is intended for use in autograph tools and services without
// including the rest of autograph and its dependencies.
//
// Prefer [the NSS
// verifier](https://searchfox.org/mozilla-central/source/security/manager/ssl/nsIContentSignatureVerifier.idl)
// in Firefox Desktop or [the rust application services
// component](https://github.com/mozilla/application-services/) in
// other Mozilla products.
//
package contentsignature // import "github.com/mozilla-services/autograph/verifier/contentsignature"

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"math/big"
)

const (
	// P256ECDSA defines an ecdsa content signature on the P-256 curve
	P256ECDSA = "p256ecdsa"

	// P256ECDSABYTESIZE defines the bytes length of a P256ECDSA signature
	P256ECDSABYTESIZE = 64

	// P384ECDSA defines an ecdsa content signature on the P-384 curve
	P384ECDSA = "p384ecdsa"

	// P384ECDSABYTESIZE defines the bytes length of a P384ECDSA signature
	P384ECDSABYTESIZE = 96

	// P521ECDSA defines an ecdsa content signature on the P-521 curve
	P521ECDSA = "p521ecdsa"

	// P521ECDSABYTESIZE defines the bytes length of a P521ECDSA signature
	P521ECDSABYTESIZE = 132

	// SignaturePrefix is a string preprended to data prior to signing
	SignaturePrefix = "Content-Signature:\x00"
)

// ContentSignature contains the parsed representation of a signature
type ContentSignature struct {
	R, S     *big.Int // fields must be exported for ASN.1 marshalling
	HashName string
	Mode     string
	X5U      string
	ID       string
	Len      int
	Finished bool
}

func (sig *ContentSignature) String() string {
	return fmt.Sprintf("ID=%s Mode=%s Len=%d HashName=%s X5U=%s Finished=%t R=%s S=%s",
		sig.ID, sig.Mode, sig.Len, sig.HashName, sig.X5U, sig.Finished, sig.R.String(), sig.S.String())
}

// VerifyData verifies a signatures on its raw, untemplated, input using a public key
func (sig *ContentSignature) VerifyData(input []byte, pubKey *ecdsa.PublicKey) bool {
	_, hash := makeTemplatedHash(input, sig.Mode)
	return sig.VerifyHash(hash, pubKey)
}

// VerifyHash verifies a signature on its templated hash using a public key
func (sig *ContentSignature) VerifyHash(hash []byte, pubKey *ecdsa.PublicKey) bool {
	return ecdsa.Verify(pubKey, hash, sig.R, sig.S)
}

// Marshal returns the R||S signature is encoded in base64 URL safe,
// following DL/ECSSA format spec from IEEE Std 1363-2000.
func (sig *ContentSignature) Marshal() (str string, err error) {
	if !sig.Finished {
		return "", fmt.Errorf("contentsignature.Marshal: unfinished cannot be encoded")
	}
	if sig.Len != P256ECDSABYTESIZE && sig.Len != P384ECDSABYTESIZE && sig.Len != P521ECDSABYTESIZE {
		return "", fmt.Errorf("contentsignature.Marshal: invalid signature length %d", sig.Len)
	}
	// write R and S into a slice of len
	// both R and S are zero-padded to the left to be exactly
	// len/2 in length
	Rstart := (sig.Len / 2) - len(sig.R.Bytes())
	Rend := (sig.Len / 2)
	Sstart := sig.Len - len(sig.S.Bytes())
	Send := sig.Len
	rs := make([]byte, sig.Len)
	copy(rs[Rstart:Rend], sig.R.Bytes())
	copy(rs[Sstart:Send], sig.S.Bytes())
	encodedsig := base64.RawURLEncoding.EncodeToString(rs)
	return fmt.Sprintf("%s", encodedsig), nil
}

// Unmarshal parses a base64 url encoded content signature
// and returns it into a ContentSignature structure that can be verified.
//
// Note this function does not set the X5U value of a signature.
func Unmarshal(signature string) (sig *ContentSignature, err error) {
	if len(signature) < 30 {
		return nil, fmt.Errorf("contentsignature: signature cannot be shorter than 30 characters, got %d", len(signature))
	}
	// decode the actual signature into its R and S values
	data, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("contentsignature: error decoding %w", err)
	}
	// Use the length to determine the mode
	sig = new(ContentSignature)
	sig.Len = len(data)
	switch sig.Len {
	case P256ECDSABYTESIZE:
		sig.Mode = P256ECDSA
	case P384ECDSABYTESIZE:
		sig.Mode = P384ECDSA
	case P521ECDSABYTESIZE:
		sig.Mode = P521ECDSA
	default:
		return nil, fmt.Errorf("contentsignature: unknown signature length %d", len(data))
	}
	sig.HashName = getSignatureHash(sig.Mode)
	// parse the signature into R and S value by splitting it in the middle
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(data[:len(data)/2])
	sig.S.SetBytes(data[len(data)/2:])
	sig.Finished = true
	return sig, nil
}

// makeTemplatedHash returns the templated sha384 of the input data. The template adds
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

// getSignatureHash returns the name of the hash function used by a given mode,
// or an empty string if the mode is unknown
func getSignatureHash(mode string) string {
	switch mode {
	case P256ECDSA:
		return "sha256"
	case P384ECDSA:
		return "sha384"
	case P521ECDSA:
		return "sha512"
	}
	return ""
}
