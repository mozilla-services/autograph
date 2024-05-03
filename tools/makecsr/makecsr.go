// This code requires a configuration file to initialize the crypto11
// library. Use the following config in a file named "crypto11.config"
//
//	{
//	"Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//	"TokenLabel": "cavium",
//	"Pin" : "$CRYPTO_USER:$PASSWORD"
//	}
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ThalesIgnite/crypto11"
)

func main() {
	var (
		keyLabel string
		ou       string
		cn       string
		email    string
	)
	flag.StringVar(&keyLabel, "l", "mykey", "Label of the key in the HSM")
	flag.StringVar(&ou, "ou", "Mozilla AMO Production Signing Service", "OrganizationalUnit of the Subject")
	flag.StringVar(&cn, "cn", "Content Signing Intermediate", "CommonName of the Subject")
	flag.StringVar(&email, "email", "foxsec@mozilla.com", "Email of the Subject")
	flag.Parse()

	p11Ctx, err := crypto11.ConfigureFromFile("crypto11.config")
	if err != nil {
		log.Fatal(err)
	}
	slots, err := p11Ctx.GetSlotList(true)
	if err != nil {
		log.Fatalf("Failed to list PKCS#11 Slots: %s", err.Error())
	}
	if len(slots) < 1 {
		log.Fatal("No slot found")
	}
	privKey, err := crypto11.FindKeyPair(nil, []byte(keyLabel))
	if err != nil {
		log.Fatal(err)
	}
	sigalg := x509.ECDSAWithSHA384
	switch privKey.(type) {
	case *crypto11.PKCS11PrivateKeyRSA:
		sigalg = x509.SHA384WithRSA

	}
	crtReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         fmt.Sprintf("%s/emailAddress=%s", cn, email),
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{ou},
			Country:            []string{"US"},
		},
		DNSNames:           []string{cn},
		SignatureAlgorithm: sigalg,
	}
	fmt.Printf("+%v\n", crtReq)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, crtReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}
