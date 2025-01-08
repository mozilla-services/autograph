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
	"maps"
	"os"
	"slices"

	"github.com/mozilla-services/autograph/crypto11"
)

var (
	allowedSigAlgs = map[string]x509.SignatureAlgorithm{
		"SHA256WithRSA": x509.SHA256WithRSA,
		// TODO(AUT-307): SHA384WithRSA is not supported by GCP, but is in AWS. Remove this when we move off AWS
		"SHA384WithRSA":   x509.SHA384WithRSA,
		"ECDSAWithSHA256": x509.ECDSAWithSHA256,
		"ECDSAWithSHA384": x509.ECDSAWithSHA384,
	}
)

func main() {
	var (
		crypto11ConfigFilePath string
		keyLabel               string
		o                      string
		ou                     string
		cn                     string
		c                      string
		st                     string
		l                      string
		dnsName                string
		email                  string
		sigAlgName             string
	)

	allowedSigNames := slices.Collect(maps.Keys(allowedSigAlgs))

	flag.StringVar(&crypto11ConfigFilePath, "crypto11Config", "crypto11-config.json", "Path to the crypto11 configuration file")
	flag.StringVar(&keyLabel, "lbl", "mykey", "Label of the key in the HSM")
	flag.StringVar(&o, "o", "Mozilla Corporation", "Organization of the Subject")
	flag.StringVar(&ou, "ou", "Mozilla AMO Production Signing Service", "OrganizationalUnit of the Subject")
	flag.StringVar(&cn, "cn", "Content Signing Intermediate", "CommonName of the Subject")
	flag.StringVar(&c, "c", "", "Country of the Subject")
	flag.StringVar(&st, "st", "", "State/Province of the Subject")
	flag.StringVar(&l, "l", "", "City/Locale of the Subject")
	flag.StringVar(&dnsName, "dnsName", "", "DNS name for use in the Subject Altenative Name")
	flag.StringVar(&email, "email", "", "email that's added to the EmailAddresses part of the Subject Alternative Name")
	flag.StringVar(&sigAlgName, "sigAlg", "", fmt.Sprintf("Signature Algorithm to use with the key. Must be one of %q", allowedSigNames))
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
		fmt.Fprintf(os.Stderr, "invalid signature algorithm %#v passed as -sigAlg, select from %q\n", sigAlgName, allowedSigNames)
		os.Exit(2)
	}

	// TODO(AUT-307): Remove this conditional and erro when we remove
	// SHA384WithRSA from the allowedSigAlgs
	if os.Getenv("KMS_PKCS11_CONFIG") != "" && sigAlg == x509.SHA384WithRSA {
		// We're on GCP, so we should tell them about the SHA384WithRSA issue
		fmt.Fprintln(os.Stderr, "SHA384WithRSA is not supported by GCP. Select another signature algorithm")
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

	csrPEM, err := generatePEMEncodedCSR(privKey, o, ou, cn, c, st, l, email, []string{dnsName}, sigAlg)
	if err != nil {
		log.Fatalf("Failed to generate CSR: %s", err.Error())
	}
	fmt.Print(string(csrPEM))
}

func generatePEMEncodedCSR(privKey any, organization, organizationalUnit, commonName, country, state, locale, email string, dnsNames []string, sigAlg x509.SignatureAlgorithm) ([]byte, error) {
	crtReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:            []string{country},
			Locality:           []string{locale},
			Province:           []string{state},
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
