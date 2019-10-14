// This code requires a configuration file to initialize the crypto11
// library. Use the following config in a file named "crypto11.config"
//      {
//      "Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//      "TokenLabel": "cavium",
//      "Pin" : "$CRYPTO_USER:$PASSWORD"
//      }
package main

import (
	"crypto/rand"
	//hwine"crypto/rsa" //hwine
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	)
	flag.StringVar(&keyLabel, "l", "mykey", "Label of the key in the HSM")
	flag.Parse()

	// We need the email address encoded as asn1.ia5
	email_utf8 := "release+certificates@mozilla.com"
	type ia5String struct {
		A string `asn1:"ia5"`
	}
	email_ia5, err := asn1.Marshal(ia5String{email_utf8})
	if err != nil {
		log.Fatal(err)
	}

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
	//hwine privKey, _ := rsa.GenerateKey(rand.Reader, 2048) //hwine
	//hwine sigalg = x509.SHA256WithRSA //hwine
	sigalg := x509.ECDSAWithSHA384
	switch privKey.(type) {
	case *crypto11.PKCS11PrivateKeyRSA:
		sigalg = x509.SHA256WithRSA
	}
	// hard code values for this cert
	crtReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "Mozilla Corporation",
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Release Engineering"},
			Country:            []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				pkix.AttributeTypeAndValue{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: email_ia5,
				},
			},
		},
		DNSNames:           []string{"Mozilla Corporation"},
		SignatureAlgorithm: sigalg,
	}
	fmt.Printf("+%v\n", crtReq)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, crtReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}
