package mar_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"go.mozilla.org/mar"
)

func Example() {
	marFile := mar.New()
	marFile.AddContent([]byte("cariboumaurice"), "/foo/bar", 640)

	// make a new rsa key and add it for signature
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa key generation failed with: %v", err)
	}
	marFile.PrepareSignature(rsaPrivKey, rsaPrivKey.Public())

	// make a new ecdsa key and add it for signature
	ecdsaPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("ecdsa key generation failed with: %v", err)
	}
	marFile.PrepareSignature(ecdsaPrivKey, ecdsaPrivKey.Public())

	// once both keys are added to the file, finalize the signature
	err = marFile.FinalizeSignatures()
	if err != nil {
		log.Fatalf("mar signature failed with error: %v", err)
	}

	// write out the MAR file
	outputMar, err := marFile.Marshal()
	if err != nil {
		log.Fatalf("mar marshalling failed with error: %v", err)
	}

	// reparse the MAR to make sure it goes through fine
	var reparsedMar mar.File
	err = mar.Unmarshal(outputMar, &reparsedMar)
	if err != nil {
		log.Fatalf("mar unmarshalling failed with error: %v", err)
	}

	// verify the signatures
	err = reparsedMar.VerifySignature(rsaPrivKey.Public())
	if err != nil {
		log.Fatalf("failed to verify rsa signature: %v", err)
	}
	err = reparsedMar.VerifySignature(ecdsaPrivKey.Public())
	if err != nil {
		log.Fatalf("failed to verify ecdsa signature: %v", err)
	}

	fmt.Printf("MAR file signed and parsed without error")

	// Output: MAR file signed and parsed without error
}
