package main

import (
	"log"

	"go.mozilla.org/autograph/signer/apk"
)

func verifyAPKSignature(sig string) error {
	apkSig, err := apk.Unmarshal(sig, []byte(inputdata))
	if err != nil {
		log.Fatal(err)
	}
	return apkSig.Verify()
}
