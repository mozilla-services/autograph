package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
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
	"go.mozilla.org/sops/aes"
	sopsyaml "go.mozilla.org/sops/yaml"
	yaml "gopkg.in/yaml.v2"
)

type signatureresponse struct {
	Ref              string `json:"ref"`
	X5U              string `json:"x5u,omitempty"`
	PublicKey        string `json:"public_key,omitempty"`
	Hash             string `json:"hash_algorithm,omitempty"`
	Encoding         string `json:"signature_encoding,omitempty"`
	Signature        string `json:"signature"`
	ContentSignature string `json:"content-signature,omitempty"`
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
			log.Printf("Response %d does not pass: %v", i, err)
			log.Printf("Response was: %+v", response)
		} else {
			log.Printf("Response %d passes verification", i)
		}
	}
	if failed {
		log.Fatal("Errors found during monitoring")
	}
}

// Verify the signature and certificate chain of a response.
//
// If an X5U value was provided, use the public key from the end entity certificate
// to verify the sig. Otherwise, use the PublicKey contained in the response.
//
// If the signature passes, verify the chain of trust maps.
func verify(sr signatureresponse) error {
	var (
		pubkey *ecdsa.PublicKey
		err    error
		data   []byte
		certs  []*x509.Certificate
	)
	if sr.X5U != "" {
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

	if sr.ContentSignature != "" {
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
			// this is the last cert, it should be self signed
			if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				return fmt.Errorf("Certificate %d is root but has different subject and issuer, should be equal", i)
			}
			if !cert.IsCA {
				return fmt.Errorf("Certificate %d is root but doesn't have CA flag", i)
			}
			if conf.RootHash != "" {
				rhash := strings.Replace(conf.RootHash, ":", "", -1)
				// We're configure to check the root hash matches expected value
				h := sha256.Sum256(cert.Raw)
				chash := fmt.Sprintf("%X", h[:])
				if rhash != chash {
					return fmt.Errorf("Certificate %d is root but does not match expected hash: expected=%s; got=%s",
						i, rhash, chash)
				}
			}
			log.Printf("Certificate %d is a valid root", i)
		} else {
			// check that cert is signed by parent
			err := cert.CheckSignatureFrom(certs[i+1])
			if err != nil {
				return fmt.Errorf("Certificate %d is not signed by parent certificate %d: %v", i, i+1, err)
			}
			log.Printf("Certificate %d has a valid signature from parent certificate %d", i, i+1)
		}
		if time.Now().Add(15 * 24 * time.Hour).After(cert.NotAfter) {
			return fmt.Errorf("Certificate %d expires in less than 15 days: notAfter=%s", i, cert.NotAfter)
		}
		if time.Now().Before(cert.NotBefore) {
			return fmt.Errorf("Certificate %d is not yet valid: notBefore=%s", i, cert.NotBefore)
		}
		log.Printf("Certificate %d is valid from %s to %s", i, cert.NotBefore, cert.NotAfter)
	}
	return nil
}

func fromBase64URL(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(b64urlTob64(s))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func b64urlTob64(s string) string {
	// convert base64url characters back to regular base64 alphabet
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return s
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
	// try to decrypt the conf using sops or load it as plaintext
	// if it's not encrypted
	decryptedConf, err := decryptConf(data)
	if err != nil {
		// decryption would have failed if the file is not encrypted,
		// in which case simply continue loading as yaml. But if the
		// file is encrypted and decryption failed, exit here.
		if err != sops.MetadataNotFound {
			return
		}
	} else {
		data = decryptedConf
	}
	err = yaml.Unmarshal(data, &cfg)
	return
}

func decryptConf(encryptedConf []byte) (decryptedConf []byte, err error) {
	store := &sopsyaml.Store{}
	metadata, err := store.UnmarshalMetadata(encryptedConf)
	if err != nil {
		return
	}
	key, err := metadata.GetDataKey()
	if err != nil {
		return
	}
	branch, err := store.Unmarshal(encryptedConf)
	if err != nil {
		return
	}
	tree := sops.Tree{Branch: branch, Metadata: metadata}
	cipher := aes.Cipher{}
	stash := make(map[string][]interface{})
	mac, err := tree.Decrypt(key, cipher, stash)
	if err != nil {
		return
	}
	originalMac, _, err := cipher.Decrypt(
		metadata.MessageAuthenticationCode,
		key,
		metadata.LastModified.Format(time.RFC3339),
	)
	if originalMac != mac {
		return
	}
	return store.Marshal(tree.Branch)
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
