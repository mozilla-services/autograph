package contentsignature // import "github.com/mozilla-services/autograph/signer/contentsignature"
import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
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

// a private struct to unmarshal asn1 signatures produced by crypto.Signer
type ecdsaAsn1Signature struct {
	R, S *big.Int
}

func (sig *ContentSignature) storeHashName(alg string) {
	sig.HashName = alg
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
		return nil, errors.Wrap(err, "contentsignature")
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

func (sig *ContentSignature) String() string {
	return fmt.Sprintf("ID=%s Mode=%s Len=%d HashName=%s X5U=%s Finished=%t R=%s S=%s",
		sig.ID, sig.Mode, sig.Len, sig.HashName, sig.X5U, sig.Finished, sig.R.String(), sig.S.String())
}
