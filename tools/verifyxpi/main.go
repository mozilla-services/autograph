package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"go.mozilla.org/autograph/signer"
	"go.mozilla.org/autograph/signer/xpi"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: verifyxpi <xpi_file> <root_pem>")
	}
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	rootContent, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		log.Fatalf("failed to read roots from path %s: %s", os.Args[2], err)
	}
	ok := roots.AppendCertsFromPEM(rootContent)
	if !ok {
		log.Fatalf("failed to add root certs to pool")
	}
	err = xpi.VerifySignedFile(signer.SignedFile(data), roots)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature ok")
}
