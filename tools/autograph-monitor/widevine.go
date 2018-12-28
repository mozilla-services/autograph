package main

import (
	"crypto/sha1"
	"encoding/base64"

	"go.mozilla.org/autograph/signer/widevine"
)

func verifyWidevineSignature(b64Sig, b64Key string) error {
	shasum := sha1.Sum([]byte(inputdata))
	digest := base64.StdEncoding.EncodeToString(shasum[:])
	return widevine.VerifySignatureFromB64(digest, b64Sig, b64Key)
}
