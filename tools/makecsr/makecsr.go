// makecsr expects your `gcloud auth login --update-adc` to have been run
// recently and the gcloud project to be set to the same one as is in the
// keyring. Also, needs to be run in a x86_64 ("amd64", whatever) Linux
// environment so that the libkmsp11 library can be loaded.
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
	"path/filepath"

	"github.com/mozilla-services/autograph/crypto11"
)

func main() {
	var (
		gcpKeyName    string
		gcpKeyRing    string
		libkmsp11Path string
		ou            string
		cn            string
		email         string
	)
	flag.StringVar(&gcpKeyName, "key", "", "The name of the key in GCP to use for signing")
	flag.StringVar(&gcpKeyRing, "keyring", "", "The full ID of the key ring in GCP that contains the key specified in -key. Be sure your local GCP auth is set into the same project.")
	flag.StringVar(&libkmsp11Path, "libkmsp11Path", "", "The file path to the libkmsp11 shared library.")
	flag.StringVar(&ou, "ou", "Mozilla AMO Production Signing Service", "OrganizationalUnit of the Subject")
	flag.StringVar(&cn, "cn", "Content Signing Intermediate", "CommonName of the Subject")
	flag.StringVar(&email, "email", "foxsec@mozilla.com", "Email of the Subject")
	flag.Parse()

	if gcpKeyName == "" {
		fmt.Fprintf(os.Stderr, "missing -key parameter\n")
		os.Exit(1)
	}
	if gcpKeyRing == "" {
		fmt.Fprintf(os.Stderr, "missing -keyring parameter\n")
		os.Exit(1)
	}

	if libkmsp11Path == "" {
		fmt.Fprintf(os.Stderr, "missing -libkmsp11Path parameter\n")
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "makecsr-")
	if err != nil {
		log.Fatalf("unable to make temp dir for configuring libkmsp11: %s", err)
	}
	libkmsp11ConfigPath := filepath.Join(dir, "libkmsp11config.yaml")
	err = os.WriteFile(libkmsp11ConfigPath, []byte(fmt.Sprintf("tokens:\n  - key_ring: %#v\n", gcpKeyRing)), 0644)
	if err != nil {
		log.Fatalf("unable to make temp file for configuring libkmsp11 at %#v: %s", libkmsp11ConfigPath, err)
	}
	os.Setenv("KMS_PKCS11_CONFIG", libkmsp11ConfigPath)

	pkcs11Config := &crypto11.PKCS11Config{
		Path: libkmsp11Path,
	}

	_, err = crypto11.Configure(pkcs11Config, crypto11.NewDefaultPKCS11Context)
	if err != nil {
		log.Fatalf("unable to configure GCP HSM (key %#v, keyring %#v) with crypto11: %s", gcpKeyName, gcpKeyRing, err)
	}
	privKey, err := crypto11.FindKeyPair(nil, []byte(gcpKeyName))
	if err != nil {
		log.Fatalf("FindKeyPair error: %s", err)
	}
	sigalg := x509.ECDSAWithSHA384
	switch privKey.(type) {
	case *crypto11.PKCS11PrivateKeyRSA:
		sigalg = x509.SHA256WithRSA

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
		log.Fatalf("CreateCertificateRequest: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}
