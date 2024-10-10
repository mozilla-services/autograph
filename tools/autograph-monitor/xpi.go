package main

import (
	"crypto/x509"
	"log"

	"github.com/mozilla-services/autograph/signer/xpi"
)

func verifyXPISignature(sig string, truststore, depTruststore *x509.CertPool) error {
	xpiSig, err := xpi.Unmarshal(sig, []byte(inputdata))
	if err != nil {
		log.Fatal(err)
	}
	err = xpiSig.VerifyWithChain(truststore)
	if err == nil || depTruststore == nil {
		return err
	}
	log.Printf("Got error %s verifying XPI signature with rel truststore trying dep truststore", err)
	return xpiSig.VerifyWithChain(depTruststore)
}
