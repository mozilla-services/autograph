package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ThalesIgnite/crypto11"
)

func usage() {
	fmt.Printf(`make an end-entity certificate on the hsm for use in content signature

usage: go run make-hsm-ee.go -i <intermediate_label> -a <appname> -c <issuer_cert_path> (-p <hsm_lib_path> -t <hsm_type> -s <hsm_pin> -validDays <days_cert_valid_from_now>)

eg. $ go run make-hsm-ee.go -i csinter1555704936 -a normandy -c issuer.pem
`)

	log.Fatal()
}
func main() {
	var (
		interKeyName, appName, hsmPath, hsmType, hsmPin, issuerCertPath string
		slots                                                           []uint
		validDays                                                       int
		err                                                             error
	)
	flag.StringVar(&interKeyName, "i", "",
		"label of the private key of the intermediate in the hsm")
	flag.StringVar(&appName, "a", "",
		"name of the application the end-entity is for (eg. remote-settings)")
	flag.StringVar(&hsmPath, "p", "/usr/lib/softhsm/libsofthsm2.so",
		"path to the hsm pkcs11 library")
	flag.StringVar(&hsmType, "t", "test",
		"type of the hsm (use 'cavium' for cloudhsm)")
	flag.StringVar(&hsmPin, "s", "0000",
		"pin to log into the hsm (use 'user:pass' on cloudhsm)")
	flag.StringVar(&issuerCertPath, "c", "", "path to the issuer intermediate cert in PEM format")
	flag.IntVar(&validDays, "validDays", 60, "number of days for the new EE cert to be valid")
	flag.Parse()

	if appName == "" || interKeyName == "" {
		usage()
	}

	issuerCertBytes, err := os.ReadFile(issuerCertPath)
	if err != nil {
		log.Fatalf("error reading issuer cert: %s", err.Error())
	}
	block, _ := pem.Decode(issuerCertBytes)
	if block == nil {
		log.Fatal("No pem block found in issuer cert")
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse issuer certificate: %s", err.Error())
	}

	p11Ctx, err := crypto11.Configure(&crypto11.PKCS11Config{
		Path:       hsmPath,
		TokenLabel: hsmType,
		Pin:        hsmPin,
	})
	if err != nil {
		log.Fatal(err)
	}
	slots, err = p11Ctx.GetSlotList(true)
	if err != nil {
		log.Fatalf("Failed to list PKCS#11 Slots: %s", err.Error())
	}
	log.Printf("Using HSM on slot %d", slots[0])
	interPriv, err := crypto11.FindKeyPair(nil, []byte(interKeyName))
	if err != nil {
		log.Fatal(err)
	}
	rng := new(crypto11.PKCS11RandReader)

	// make a keypair for the end-entity
	eePriv, err := ecdsa.GenerateKey(elliptic.P384(), rng)
	if err != nil {
		log.Fatal(err)
	}
	eePub := eePriv.Public()

	expiresAt := time.Now().AddDate(0, 0, validDays)
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"Mountain View"},
			CommonName:         appName + ".content-signature.mozilla.org",
		},
		DNSNames:           []string{appName + ".content-signature.mozilla.org"},
		NotBefore:          time.Now().AddDate(0, 0, -30), // start 30 days ago
		NotAfter:           expiresAt,
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		IsCA:               false,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}
	eeCertBytes, err := x509.CreateCertificate(
		rng, certTpl, issuer, eePub, interPriv)
	if err != nil {
		log.Fatalf("create cert failed: %v", err)
	}

	// date format explanation https://golang.org/src/time/format.go?h=stdLongMonth#L88
	outputBasename := fmt.Sprintf("%s.content-signature.mozilla.org-%s", appName, expiresAt.UTC().Format("20060102"))

	var eePem bytes.Buffer
	err = pem.Encode(&eePem, &pem.Block{Type: "CERTIFICATE", Bytes: eeCertBytes})
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(outputBasename+".crt", eePem.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	eePrivBytes, err := x509.MarshalECPrivateKey(eePriv)
	if err != nil {
		log.Fatal(err)
	}

	secp384r1ECParams := "-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n"

	var eePrivPem bytes.Buffer
	err = pem.Encode(&eePrivPem,
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: eePrivBytes})
	if err != nil {
		log.Fatal(err)
	}
	msgBody := fmt.Sprintf("%s%s\n", secp384r1ECParams, eePrivPem.Bytes())
	err = os.WriteFile(outputBasename+".key", []byte(msgBody), 0644)
	if err != nil {
		log.Fatal(err)
	}
}
