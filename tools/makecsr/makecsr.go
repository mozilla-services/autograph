// If you're looking for how this code has been invoked, take a look at our
// private hsm repo.
//
// See the README.md for more information about what this code needs to operate
// correctly.
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

var (
	allowedSigAlgs = map[string]x509.SignatureAlgorithm{
		"SHA256WithRSA":   x509.SHA256WithRSA,
		"SHA384WithRSA":   x509.SHA384WithRSA,
		"ECDSAWithSHA256": x509.ECDSAWithSHA256,
		"ECDSAWithSHA384": x509.ECDSAWithSHA384,
	}
)

func main() {
	var (
		crypto11ConfigFilePath string
		keyLabel               string
		ou                     string
		cn                     string
		dnsName                string
		email                  string
		sigAlgName             string
	)

	flag.StringVar(&crypto11ConfigFilePath, "crypto11Config", "crypto11-config.json", "Path to the crypto11 configuration file")
	flag.StringVar(&keyLabel, "l", "mykey", "Label of the key in the HSM")
	flag.StringVar(&ou, "ou", "Mozilla AMO Production Signing Service", "OrganizationalUnit of the Subject")
	flag.StringVar(&cn, "cn", "Content Signing Intermediate", "CommonName of the Subject")
	flag.StringVar(&dnsName, "dnsName", "", "DNS name for use in the Subject Altenative Name")
	flag.StringVar(&email, "email", "", "email that's added to the EmailAddresses part of the Subject Alternative Name")
	flag.StringVar(&sigAlgName, "sigAlg", "", fmt.Sprintf("Signature Algorithm to use with the key. Must be one of %q", mapKeysAsSlice(allowedSigAlgs)))
	flag.Parse()

	if dnsName == "" {
		fmt.Fprintln(os.Stderr, "-dnsName is a required option")
		flag.Usage()
		os.Exit(2)
	}

	if keyLabel == "" {
		fmt.Fprintln(os.Stderr, "-l is a required option")
		flag.Usage()
		os.Exit(2)
	}

	if sigAlgName == "" {
		fmt.Fprintln(os.Stderr, "-sigAlg is a required option")
		flag.Usage()
		os.Exit(2)
	}
	sigAlg, ok := allowedSigAlgs[sigAlgName]
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid signature algorithm %#v passed as -sigAlg, select from %q\n", sigAlgName, mapKeysAsSlice(allowedSigAlgs))
		os.Exit(2)
	}

	p11Ctx, err := crypto11.ConfigureFromFile(crypto11ConfigFilePath)
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

	// FIXME use nameConstraints and allow multiple dnsNames?
	csrPEM, err := generatePEMEncodedCSR(privKey, ou, cn, email, []string{dnsName}, sigAlg)
	if err != nil {
		log.Fatalf("Failed to generate CSR: %s", err.Error())
	}
	fmt.Print(string(csrPEM))
}

func generatePEMEncodedCSR(privKey any, organizationalUnit, commonName, email string, dnsNames []string, sigAlg x509.SignatureAlgorithm) ([]byte, error) {
	crtReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{organizationalUnit},
			Country:            []string{"US"},
		},
		DNSNames:           dnsNames,
		SignatureAlgorithm: sigAlg,
	}

	if email != "" {
		crtReq.EmailAddresses = []string{email}
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, crtReq, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed in CreateCertificateRequest: %w", err)
	}

	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return out, nil
}

// mapKeysAsSlice returns the keys of a map as a slice. Once we're on Go 1.23,
// we can use `slices.Collect(map.Keys(..))` instead of this.
func mapKeysAsSlice[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
