// This code requires a configuration file to initialize the crypto11
// library. Use the following config in a file named "crypto11.config"
//
// For AWS, this file will look something like:
//
//	{
//	"Path" : "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
//	"TokenLabel": "cavium",
//	"Pin" : "$CRYPTO_USER:$PASSWORD"
//	}
//
// For GCP, this file will look something like:
//
//	{
//	"Path": "/path/to/libkmsp11.so",
//	"TokenLabel": "gcp"
//	}
//
// You will additionally need a kmsp11 yml configuration file created and
// specified in the KMS_PKCS11_CONFIG environment variable. This will look something like:
// ---
// tokens:
//   - key_ring: projects/autograph/locations/us-west-2/keyRings/autograph-keyring
//   - label: gcp
//
// Note that the label must match between the two configuration files.
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

	"github.com/mozilla-services/autograph/crypto11"
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
	crtReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         fmt.Sprintf("%s/emailAddress=%s", cn, email),
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{ou},
			Country:            []string{"US"},
		},
		DNSNames: []string{cn},
	}
	// Google's KMS library automatically detects the correct signature
	// algorithm based on the key given; no need to specify it.
	if os.Getenv("KMS_PKCS11_CONFIG") == "" {
		sigalg := x509.ECDSAWithSHA384
		switch privKey.(type) {
		case *crypto11.PKCS11PrivateKeyRSA:
			sigalg = x509.SHA384WithRSA

		}
		crtReq.SignatureAlgorithm = sigalg
	}
	fmt.Printf("+%v\n", crtReq)
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, crtReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}
