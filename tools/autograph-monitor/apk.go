package main

import (
	"log"

	"github.com/mozilla-services/autograph/signer/apk"
)

func verifyAPKSignature(sig string) error {
	apkSig, err := apk.Unmarshal(sig, []byte(inputdata))
	if err != nil {
		log.Fatal(err)
	}
	return apkSig.Verify()
}
