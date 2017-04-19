package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mozilla.org/hawk"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"
	yaml "gopkg.in/yaml.v2"
)

type signatureresponse struct {
	Ref       string `json:"ref"`
	Type      string `json:"type"`
	SignerID  string `json:"signer_id"`
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature"`
}

type configuration struct {
	URL           string `yaml:"url"`
	MonitoringKey string `yaml:"monitoringkey"`
	RootHash      string `yaml:"security.content.signature.root_hash"`
}

var conf configuration

const inputdata string = "AUTOGRAPH MONITORING"

func main() {
	var err error
	confdir := "."
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		confdir = os.Getenv("LAMBDA_TASK_ROOT")
	}
	// load the local configuration file
	conf, err = loadConf(confdir + "/monitor.autograph.yaml")
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	log.Println("Retrieving monitoring data from", conf.URL)
	req, err := http.NewRequest("GET", conf.URL+"__monitor__", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", makeAuthHeader(req, "monitor", conf.MonitoringKey))
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil || resp == nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Request failed with %q", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// verify that we got a proper signature response, with a valid signature
	var responses []signatureresponse
	err = json.Unmarshal(body, &responses)
	if err != nil {
		log.Fatal(err)
	}
	failed := false
	for i, response := range responses {
		err = verify(response)
		if err != nil {
			failed = true
			log.Printf("Response %d from signer %q does not pass: %v", i, err, response.SignerID)
			log.Printf("Response was: %+v", response)
		} else {
			log.Printf("Response %d from signer %q passes verification", i, response.SignerID)
		}
	}
	if failed {
		log.Fatal("Errors found during monitoring")
	}
}

// validate the signature and certificate chain of a content signature response
//
// If an X5U value was provided, use the public key from the end entity certificate
// to verify the sig. Otherwise, use the PublicKey contained in the response.
//
// If the signature passes, verify the chain of trust maps.
func validateContentSignature(cs string) error {
	var (
		pubkey *ecdsa.PublicKey
		err    error
		data   []byte
		certs  []*x509.Certificate
	)
	sig, err := contentsignature.Unmarshal(cs)
	if err != nil {
		log.Fatal(err)
	}
	if sig.X5U != "" {
		certs, err = getX5U(sr.X5U)
		if err != nil {
			return err
		}
		if len(certs) < 2 {
			return fmt.Errorf("Found %d certs in X5U, expected at least 2", len(certs))
		}
		// certs[0] is the end entity
		pubkey = certs[0].PublicKey.(*ecdsa.PublicKey)
	} else {
		pubkey, err = parsePublicKeyFromB64(sr.PublicKey)
		if err != nil {
			return err
		}
	}

	switch != "" {
		data = make([]byte, len("Content-Signature:\x00")+len(inputdata))
		copy(data[:len("Content-Signature:\x00")], []byte("Content-Signature:\x00"))
		copy(data[len("Content-Signature:\x00"):], inputdata)
	} else {
		data = make([]byte, len(inputdata))
		copy(data, inputdata)
	}
	datahash, err := digest(data, sr.Hash)
	if err != nil {
		return err
	}
	sigBytes, err := fromBase64URL(sr.Signature)
	if err != nil {
		return err
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sigBytes[:len(sigBytes)/2])
	s.SetBytes(sigBytes[len(sigBytes)/2:])
	if !ecdsa.Verify(pubkey, datahash, r, s) {
		return fmt.Errorf("Signature verification failed")
	}

	if certs != nil {
		return verifyCertChain(certs)
	}

	return nil
}

func getX5U(x5u string) (certs []*x509.Certificate, err error) {
	resp, err := http.Get(x5u)
	if err != nil {
		return certs, fmt.Errorf("Failed to retrieve X5U %s: %v", x5u, err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	// the first row must contain BEGIN CERT for the end entity
	scanner.Scan()
	if scanner.Text() != "-----BEGIN CERTIFICATE-----" {
		return certs, fmt.Errorf("Invalid X5U format for %s: first row isn't BEGIN CERTIFICATE", x5u)
	}
	var certPEM []byte
	certPEM = append(certPEM, scanner.Bytes()...)
	certPEM = append(certPEM, byte('\n'))
	for scanner.Scan() {
		certPEM = append(certPEM, scanner.Bytes()...)
		certPEM = append(certPEM, byte('\n'))
		if scanner.Text() == "-----END CERTIFICATE-----" {
			// end of the current cert. Parse it, store it
			// and move on to next cert
			block, _ := pem.Decode(certPEM)
			if block == nil {
				return certs, fmt.Errorf("Failed to parse certificate PEM")
			}
			certX509, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return certs, fmt.Errorf("Could not parse X.509 certificate: %v", err)

			}
			certs = append(certs, certX509)
			certPEM = nil
		}
	}
	return certs, nil
}

func parsePublicKeyFromB64(b64PubKey string) (pubkey *ecdsa.PublicKey, err error) {
	keyBytes, err := fromBase64URL(b64PubKey)
	if err != nil {
		return pubkey, fmt.Errorf("Failed to parse public key base64: %v", err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return pubkey, fmt.Errorf("Failed to parse public key DER: %v", err)
	}
	pubkey = keyInterface.(*ecdsa.PublicKey)
	return pubkey, nil
}

func verifyCertChain(certs []*x509.Certificate) error {
	for i, cert := range certs {
		if (i + 1) == len(certs) {
			err := verifyRoot(cert)
			if err != nil {
				return fmt.Errorf("Certificate %d %q is root but fails validation: %v",
					i, cert.Subject.CommonName, err)
			}
			log.Printf("Certificate %d %q is a valid root", i, cert.Subject.CommonName)
		} else {
			// check that cert is signed by parent
			err := cert.CheckSignatureFrom(certs[i+1])
			if err != nil {
				return fmt.Errorf("Certificate %d %q is not signed by parent certificate %d %q: %v",
					i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName, err)
			}
			log.Printf("Certificate %d %q has a valid signature from parent certificate %d %q",
				i, cert.Subject.CommonName, i+1, certs[i+1].Subject.CommonName)
		}
		if time.Now().Add(15 * 24 * time.Hour).After(cert.NotAfter) {
			return fmt.Errorf("Certificate %d %q expires in less than 15 days: notAfter=%s",
				i, cert.Subject.CommonName, cert.NotAfter)
		}
		if time.Now().Before(cert.NotBefore) {
			return fmt.Errorf("Certificate %d %q is not yet valid: notBefore=%s",
				i, cert.Subject.CommonName, cert.NotBefore)
		}
		log.Printf("Certificate %d %q is valid from %s to %s",
			i, cert.Subject.CommonName, cert.NotBefore, cert.NotAfter)
	}
	return nil
}

func verifyRoot(cert *x509.Certificate) error {
	// this is the last cert, it should be self signed
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return fmt.Errorf("subject does not match issuer, should be equal")
	}
	if !cert.IsCA {
		return fmt.Errorf("missing IS CA extension")
	}
	if conf.RootHash != "" {
		rhash := strings.Replace(conf.RootHash, ":", "", -1)
		// We're configure to check the root hash matches expected value
		h := sha256.Sum256(cert.Raw)
		chash := fmt.Sprintf("%X", h[:])
		if rhash != chash {
			return fmt.Errorf("hash does not match expected root: expected=%s; got=%s", rhash, chash)
		}
	}
	hasCodeSigningExtension := false
	for _, ext := range cert.ExtKeyUsage {
		if ext == x509.ExtKeyUsageCodeSigning {
			hasCodeSigningExtension = true
			break
		}
	}
	if !hasCodeSigningExtension {
		return fmt.Errorf("missing codeSigning key usage extension")
	}
	return nil
}

func digest(data []byte, alg string) (hashed []byte, err error) {
	var md hash.Hash
	switch alg {
	case "sha1":
		md = sha1.New()
	case "sha256":
		md = sha256.New()
	case "sha384":
		md = sha512.New384()
	case "sha512":
		md = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
	md.Write(data)
	hashed = md.Sum(nil)
	return
}
func loadConf(path string) (cfg configuration, err error) {
	log.Println("Accessing configuration from", path)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err = decrypt.Data(data, "yaml")
	if err != nil {
		if err == sops.MetadataNotFound {
			// not an encrypted file
			confData = data
		} else {
			return
		}
	}
	err = yaml.Unmarshal(confData, &cfg)
	return
}

func makeAuthHeader(req *http.Request, user, token string) string {
	auth := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   user,
			Key:  token,
			Hash: sha256.New},
		0)
	auth.Ext = fmt.Sprintf("%d", time.Now().Nanosecond())
	payloadhash := auth.PayloadHash("application/json")
	payloadhash.Write([]byte(""))
	auth.SetHash(payloadhash)
	return auth.RequestHeader()
}
