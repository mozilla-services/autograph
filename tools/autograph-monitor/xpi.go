package main

import (
	"crypto/x509"
	"log"

	"go.mozilla.org/autograph/signer/xpi"
)

func verifyXPISignature(sig string, truststore *x509.CertPool) error {
	pkcs7Sig, err := xpi.Unmarshal(sig, []byte(inputdata))
	if err != nil {
		log.Fatal(err)
	}
	return pkcs7Sig.VerifyWithChain(truststore)
}
