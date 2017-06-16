package contentsignature // import "go.mozilla.org/autograph/signer/contentsignature"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/pkg/errors"
)

// ContentSignature contains the parsed representation of a signature
type ContentSignature struct {
	R, S      *big.Int // fields must be exported for ASN.1 marshalling
	HashName  string
	CurveName string
	X5U       string
	ID        string
	Len       int
	Finished  bool
}

func (sig *ContentSignature) storeHashName(alg string) {
	sig.HashName = alg
}

// VerifyData verifies a signatures on its raw, untemplated, input using a public key
func (sig *ContentSignature) VerifyData(input []byte, pubKey *ecdsa.PublicKey) bool {
	_, hash := makeTemplatedHash(input, sig.CurveName)
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
	if sig.X5U != "" {
		return fmt.Sprintf("x5u=\"%s\";%s=%s", sig.X5U, sig.CurveName, encodedsig), nil
	}
	return fmt.Sprintf("keyid=%s;%s=%s", sig.ID, sig.CurveName, encodedsig), nil
}

// Unmarshal parses the string representation of a content signature
// and returns it into a ContentSignature structure that can be verified
func Unmarshal(signature string) (sig *ContentSignature, err error) {
	if len(signature) < 50 {
		return nil, errors.Errorf("contentsignature: signature cannot be shorter than 50 characters, got %d", len(signature))
	}
	sep := strings.Index(signature, ";")
	if sep < 5 {
		return nil, errors.Errorf("contentsignature: signature separator location cannot be smaller than 5, got %d", sep)
	}
	sepval := strings.Index(signature[sep+1:], "=")
	if sepval < 8 {
		return nil, errors.Errorf("contentsignature: signature value location cannot be smaller than 8, got %d", sepval)
	}
	// parse the components of the string representation into their respective fields
	sig = new(ContentSignature)
	sig.CurveName = signature[sep+1 : sep+1+sepval]
	switch sig.CurveName {
	case P256ECDSA:
		sig.HashName = "sha256"
		sig.Len = getSignatureLen(elliptic.P256().Params().BitSize)
	case P384ECDSA:
		sig.HashName = "sha384"
		sig.Len = getSignatureLen(elliptic.P384().Params().BitSize)
	case P521ECDSA:
		sig.HashName = "sha512"
		sig.Len = getSignatureLen(elliptic.P521().Params().BitSize)
	default:
		return nil, errors.Errorf("contentsignature: unknown curve name %q", sig.CurveName)
	}
	if strings.HasPrefix(signature, "x5u=") {
		sig.X5U = signature[5 : sep-1]
	} else {
		// if no x5u is present, grab the key id
		sig.ID = signature[6:sep]
	}
	// decode the actual signature into its R and S values
	sigdata := signature[sep+1+sepval+1:]
	data, err := base64.RawURLEncoding.DecodeString(sigdata)
	if err != nil {
		return nil, errors.Wrap(err, "contentsignature")
	}
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(data[:len(data)/2])
	sig.S.SetBytes(data[len(data)/2:])
	sig.Finished = true
	return sig, nil
}

func (sig *ContentSignature) String() string {
	return fmt.Sprintf("R=%s S=%s HashName=%s	CurveName=%s X5U=%s ID=%s Len=%d Finished=%t",
		sig.R.String(), sig.S.String(), sig.HashName, sig.CurveName, sig.X5U, sig.ID, sig.Len, sig.Finished)
}
