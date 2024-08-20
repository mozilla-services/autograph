package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func main() {
	var (
		rootPriv, interPriv crypto.PrivateKey
		rootPub, interPub   crypto.PublicKey
		slots               []uint
		noHSM               bool
		err                 error
	)
	flag.BoolVar(&noHSM, "no-hsm", false,
		"generate keys locally instead of using an hsm")
	flag.Parse()

	rootKeyName := []byte(fmt.Sprintf("csroot%d", time.Now().Unix()))
	if !noHSM {
		p11Ctx, err := crypto11.Configure(&crypto11.PKCS11Config{
			Path:       "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test",
			Pin:        "0000",
		})
		if err != nil {
			log.Fatal(err)
		}
		slots, err = p11Ctx.GetSlotList(true)
		if err != nil {
			log.Fatalf("Failed to list PKCS#11 Slots: %s", err.Error())
		}
		log.Printf("Using HSM on slot %d", slots[0])
		rootPriv, err = crypto11.GenerateECDSAKeyPairOnSlot(
			slots[0], rootKeyName, rootKeyName, elliptic.P384())
		if err != nil {
			log.Fatal(err)
		}
		rootPub = rootPriv.(*crypto11.PKCS11PrivateKeyECDSA).Public()
	} else {
		rootPriv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		rootPub = rootPriv.(*ecdsa.PrivateKey).Public()
	}

	caTpl := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Mozilla"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"Mountain View"},
		},
		NotBefore:             time.Now().AddDate(0, -2, -2), // start 2 months and 2 days ago
		NotAfter:              time.Now().AddDate(30, 0, 0),  // valid for 30 years
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(rootKeyName)

	rootCertBytes, err := x509.CreateCertificate(
		rand.Reader, caTpl, caTpl, rootPub, rootPriv)
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

	interKeyName := []byte(fmt.Sprintf("csinter%d", time.Now().Unix()))
	if !noHSM {
		interPriv, err = crypto11.GenerateECDSAKeyPairOnSlot(
			slots[0], interKeyName, interKeyName, elliptic.P384())
		if err != nil {
			log.Fatal(err)
		}
		interPub = interPriv.(*crypto11.PKCS11PrivateKeyECDSA).Public()

	} else {
		interPriv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		interPub = interPriv.(*ecdsa.PrivateKey).Public()

	}

	caTpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	caTpl.Subject.CommonName = string(interKeyName)
	caTpl.PermittedDNSDomainsCritical = true
	caTpl.PermittedDNSDomains = []string{".content-signature.mozilla.org"}
	caTpl.NotBefore = time.Now().AddDate(0, -2, -1) // start 2 months and 1 day ago
	caTpl.NotAfter = time.Now().AddDate(10, 0, 0)   // valid for 10 years
	interCertBytes, err := x509.CreateCertificate(
		rand.Reader, caTpl, rootCert, interPub, rootPriv)
	if err != nil {
		log.Fatalf("create inter ca failed: %v", err)
	}

	var interPem bytes.Buffer
	err = pem.Encode(&interPem, &pem.Block{Type: "CERTIFICATE", Bytes: interCertBytes})
	if err != nil {
		log.Fatal(err)
	}

	// verify the chain
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPem.Bytes())
	if !ok {
		log.Fatal("failed to load root cert into truststore")
	}
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: caTpl.ExtKeyUsage,
	}
	inter, err := x509.ParseCertificate(interCertBytes)
	if err != nil {
		log.Fatal("failed to parse intermediate certificate: %w", err)
	}
	_, err = inter.Verify(opts)
	if err != nil {
		log.Fatal("failed to verify intermediate chain to root: %w", err)
	}

	rootTmpfile, err := os.CreateTemp("", "csrootcert")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := rootTmpfile.Write(rootPem.Bytes()); err != nil {
		log.Fatal(err)
	}
	if err := rootTmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	interTmpfile, err := os.CreateTemp("", "csintercert")
	if err != nil {
		log.Fatal(err)
	}
	if _, err := interTmpfile.Write(interPem.Bytes()); err != nil {
		log.Fatal(err)
	}
	if err := interTmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("root key name: %s\nroot cert path: %s\ninter key name: %s\ninter cert path: %s\n",
		rootKeyName, rootTmpfile.Name(), interKeyName, interTmpfile.Name())

	if noHSM {
		rootPrivBytes, err := x509.MarshalECPrivateKey(rootPriv.(*ecdsa.PrivateKey))
		if err != nil {
			log.Fatal(err)
		}
		var rootPrivPem bytes.Buffer
		err = pem.Encode(&rootPrivPem,
			&pem.Block{Type: "EC PRIVATE KEY", Bytes: rootPrivBytes})
		if err != nil {
			log.Fatal(err)
		}
		rootPrivTmpfile, err := os.CreateTemp("", "csrootkey")
		if err != nil {
			log.Fatal(err)
		}
		if _, err := rootPrivTmpfile.Write(rootPrivPem.Bytes()); err != nil {
			log.Fatal(err)
		}
		if err := rootPrivTmpfile.Close(); err != nil {
			log.Fatal(err)
		}

		interPrivBytes, err := x509.MarshalECPrivateKey(interPriv.(*ecdsa.PrivateKey))
		if err != nil {
			log.Fatal(err)
		}
		var interPrivPem bytes.Buffer
		err = pem.Encode(&interPrivPem,
			&pem.Block{Type: "EC PRIVATE KEY", Bytes: interPrivBytes})
		if err != nil {
			log.Fatal(err)
		}
		interPrivTmpfile, err := os.CreateTemp("", "csinterkey")
		if err != nil {
			log.Fatal(err)
		}
		if _, err := interPrivTmpfile.Write(interPrivPem.Bytes()); err != nil {
			log.Fatal(err)
		}
		if err := interPrivTmpfile.Close(); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("root privkey path: %s\ninter privkey path: %s\n",
			rootPrivTmpfile.Name(), interPrivTmpfile.Name())
	}
}
