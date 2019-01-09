package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"
)

func main() {
	p11Ctx, err := crypto11.Configure(&crypto11.PKCS11Config{
		Path:       "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "test",
		Pin:        "0000",
	})
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

	rootKeyName := []byte(fmt.Sprintf("csroot%d", time.Now().Unix()))
	rootPriv, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], rootKeyName, rootKeyName, elliptic.P384())
	if err != nil {
		log.Fatal(err)
	}

	caTpl := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Mozilla"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Mountain View"},
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(rootKeyName)

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, rootPriv.Public(), rootPriv)
	if err != nil {
		log.Fatalf("create ca failed: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		log.Fatal(err)
	}

	var rootPem bytes.Buffer
	err = pem.Encode(&rootPem, &pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("=== Root ===\nHSM key name: %s\n%s\n\n", rootKeyName, rootPem.Bytes())

	interKeyName := []byte(fmt.Sprintf("csinter%d", time.Now().Unix()))
	interPriv, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], interKeyName, interKeyName, elliptic.P384())
	if err != nil {
		log.Fatal(err)
	}

	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(interKeyName)
	caTpl.PermittedDNSDomainsCritical = true
	caTpl.PermittedDNSDomains = []string{".content-signature.mozilla.org"}
	interCertBytes, err := x509.CreateCertificate(rand.Reader, caTpl, rootCert, interPriv.Public(), rootPriv)
	if err != nil {
		log.Fatalf("create inter ca failed: %v", err)
	}

	var interPem bytes.Buffer
	err = pem.Encode(&interPem, &pem.Block{Type: "CERTIFICATE", Bytes: interCertBytes})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("=== Intermediate ===\nHSM key name: %s\n%s\n", interKeyName, interPem.Bytes())

	// verify the chain
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPem.Bytes())
	if !ok {
		err = errors.New("failed to load root cert into truststore")
		return
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	inter, err := x509.ParseCertificate(interCertBytes)
	if err != nil {
		err = errors.Wrap(err, "failed to parse intermediate certificate")
		return
	}
	_, err = inter.Verify(opts)
	if err != nil {
		err = errors.Wrap(err, "failed to verify intermediate chain to root")
		return
	}
}
