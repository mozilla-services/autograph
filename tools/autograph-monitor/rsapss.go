package main

import (
	"crypto/sha1"
	"encoding/base64"

	"go.mozilla.org/autograph/signer/rsapss"
)

func verifyRsapssSignature(b64Sig, b64Key string) error {
	shasum := sha1.Sum([]byte(inputdata))
	digest := base64.StdEncoding.EncodeToString(shasum[:])
	return rsapss.VerifySignatureFromB64(digest, b64Sig, b64Key)
}
