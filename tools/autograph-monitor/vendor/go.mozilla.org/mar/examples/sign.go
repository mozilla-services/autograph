package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

	"go.mozilla.org/mar"
)

func main() {
	var file, refile mar.File
	if len(os.Args) < 3 {
		log.Fatal("usage: %s <input mar> <output mar>", os.Args[0])
	}
	input, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("Error while opening fd", err)
	}
	err = mar.Unmarshal(input, &file)
	if err != nil {
		log.Fatal(err)
	}

	// flush the signatures, we'll make new ones
	file.SignaturesHeader.NumSignatures = uint32(0)
	file.Signatures = nil

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	file.PrepareSignature(rsaKey, rsaKey.Public())

	// once both keys are added to the file, finalize the signature
	err = file.FinalizeSignatures()
	if err != nil {
		log.Fatal(err)
	}

	// write out the MAR file
	output, err := file.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("--- MAR file has been resigned ---")
	ioutil.WriteFile(os.Args[2], output, 0644)
	// reparse for testing, and verify signature
	err = mar.Unmarshal(output, &refile)
	if err != nil {
		log.Fatal(err)
	}

	err = refile.VerifySignature(rsaKey.Public())
	if err != nil {
		log.Fatal(err)
	}

	// make a certificate from the keys to verify signatures with signmar
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "testmarsig",
			Organization:       []string{"Mozilla"},
			OrganizationalUnit: []string{"Firefox"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	rsaDerBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, rsaKey.Public(), rsaKey)
	if err != nil {
		log.Fatal(err)
	}
	fname := fmt.Sprintf("/tmp/%x.der", sha256.Sum256(rsaDerBytes))
	ioutil.WriteFile(fname, rsaDerBytes, 0640)
	fmt.Printf("rsa cert written to %s\n", fname)
}
