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
	"crypto/rsa" //hwine
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
	)
	flag.StringVar(&keyLabel, "l", "mykey", "Label of the key in the HSM")
	flag.Parse()

	// We need the email address encoded as asn1.ia5 - use technique
	// from pkix test code
	type ia5String struct {
		A string `asn1:"ia5"`
	}

	// hard code values for this cert
	email_utf8 := "release+certificates@mozilla.com"
	locality := "Mountain View"
	state := "California"
	organization := "Mozilla Corporation"
	unit := "Release Engineering"
	country := "US"

	var sigalg x509.SignatureAlgorithm
	var privKey *rsa.PrivateKey

	_, err := os.Stat("/opt/cloudhsm/bin/configure")
	if err == nil {
		// we're on a cloud HSM machine
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
		sigalg = x509.ECDSAWithSHA384
		switch privKey.(type) {
		case *crypto11.PKCS11PrivateKeyRSA:
			sigalg = x509.SHA256WithRSA
		}
	} else {
		// testing mode
		privKey, _ = rsa.GenerateKey(rand.Reader, 2048) //hwine
		sigalg = x509.SHA256WithRSA                     //hwine
		// make sure this isn't confused with anything else
		organization = "TEST BOGUS"
	}
	crtReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         organization,
			Locality:           []string{locality},
			Province:           []string{state},
			Organization:       []string{organization},
			OrganizationalUnit: []string{unit},
			Country:            []string{country},
			ExtraNames: []pkix.AttributeTypeAndValue{
				pkix.AttributeTypeAndValue{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: ia5String{email_utf8},
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
