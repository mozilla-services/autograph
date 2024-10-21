package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer/apk2"
	"github.com/mozilla-services/autograph/signer/contentsignature"
	"github.com/mozilla-services/autograph/signer/contentsignaturepki"
	"github.com/mozilla-services/autograph/signer/genericrsa"
	"github.com/mozilla-services/autograph/signer/gpg2"
	"github.com/mozilla-services/autograph/signer/mar"
	"github.com/mozilla-services/autograph/signer/xpi"
	"go.mozilla.org/hawk"
)

type configuration struct {
	origAutographURL string
	requestURL       string
	monitoringKey    string
	env              string
	rootHashes       []string
	truststore       *x509.CertPool

	// hashes and keystore for verifying XPI dep signers
	depRootHashes []string
	depTruststore *x509.CertPool

	// notifier raises and resolves warnings
	notifier Notifier
}

const inputdata string = "AUTOGRAPH MONITORING"

func main() {
	autographURLEnvVar := strings.TrimSpace(os.Getenv("AUTOGRAPH_URL"))
	if autographURLEnvVar == "" {
		log.Fatal("AUTOGRAPH_URL must be set to the base url of the autograph service")
	}
	requestURL, err := rawAutographURLToMonitorEndpoint(autographURLEnvVar)
	if err != nil {
		log.Fatalf("failed to turn AUTOGRAPH_URL into a monitor endpoint url: %s", err)
	}
	conf := &configuration{
		origAutographURL: autographURLEnvVar,
		requestURL:       requestURL,
	}

	conf.monitoringKey = os.Getenv("AUTOGRAPH_KEY")
	if conf.monitoringKey == "" {
		log.Fatal("AUTOGRAPH_KEY must be set to the api monitoring key")
	}

	// configure monitor to check responses against Fx stage or
	// prod or autograph dev code signing PKI roots and CA root
	// certs defined in constants.go
	conf.env = os.Getenv("AUTOGRAPH_ENV")
	var rootErr, depErr error
	switch conf.env {
	case "dev":
		conf.truststore, conf.rootHashes, rootErr = loadCertsToTruststore(firefoxPkiDevRoots)
	case "stage":
		conf.truststore, conf.rootHashes, rootErr = loadCertsToTruststore(firefoxPkiStageRoots)
	case "prod":
		conf.truststore, conf.rootHashes, rootErr = loadCertsToTruststore(firefoxPkiProdRoots)
		conf.depTruststore, conf.depRootHashes, depErr = loadCertsToTruststore(firefoxPkiStageRoots)
	default:
		_, conf.rootHashes, rootErr = loadCertsToTruststore(firefoxPkiLocalDevRoots)
	}

	if rootErr != nil {
		rootErr = fmt.Errorf("failed to load truststore root certificates: %w", rootErr)
	}
	if depErr != nil {
		depErr = fmt.Errorf("failed to load depTruststore root certificates: %w", depErr)
	}

	err = errors.Join(rootErr, depErr)
	if err != nil {
		log.Fatalf("%s", err)
	}

	if os.Getenv("AUTOGRAPH_ROOT_HASH") != "" {
		conf.rootHashes = append(conf.rootHashes, strings.ToUpper(os.Getenv("AUTOGRAPH_ROOT_HASH")))
		log.Printf("Appending root hash from env var AUTOGRAPH_ROOT_HASH=%q\n", os.Getenv("AUTOGRAPH_ROOT_HASH"))
	}

	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		// we are inside a lambda environment so run as lambda
		lambda.Start(func() error { return Handler(conf, http.DefaultClient) })
	} else {
		err := Handler(conf, http.DefaultClient)
		if err != nil {
			log.Fatalf("Unhandled exception from monitor: %s", err)
		}
		os.Exit(0)
	}
}

func rawAutographURLToMonitorEndpoint(autographURLEnvVar string) (string, error) {
	baseURL, err := url.Parse(autographURLEnvVar)
	if err != nil {
		return "", fmt.Errorf("failed to parse AUTOGRAPH_URL as url: %s", err)
	}
	if baseURL.Scheme != "https" && baseURL.Scheme != "http" {
		return "", fmt.Errorf("AUTOGRAPH_URL %#v must be an https:// (or http:// url in testing)", autographURLEnvVar)
	}
	if baseURL.Host == "" {
		return "", fmt.Errorf("AUTOGRAPH_URL %#v is missing a host field. Parsed as %#v", autographURLEnvVar, baseURL)
	}
	requestURL := baseURL.JoinPath("/__monitor__")
	return requestURL.String(), nil
}

// Helper function to load a series of certificates and their hashes to a given truststore and hash list
func loadCertsToTruststore(pemStrings []string) (*x509.CertPool, []string, error) {
	var hashArr = []string{}
	var truststore = x509.NewCertPool()
	for _, str := range pemStrings {
		block, _ := pem.Decode([]byte(str))
		if block == nil {
			log.Printf("Failed to parse PEM certificate")
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		truststore.AddCert(cert)
		hashArr = append(hashArr, fmt.Sprintf("%X", sha256.Sum256(cert.Raw)))
	}
	return truststore, hashArr, nil
}

// Handler is a wrapper around monitor() that performs garbage collection
// before returning
func Handler(conf *configuration, client *http.Client) (err error) {
	defer func() {
		// force gc run
		// https://bugzilla.mozilla.org/show_bug.cgi?id=1621133
		t1 := time.Now()
		runtime.GC()
		log.Println("Garbage collected in", time.Since(t1))
	}()
	return monitor(conf, client)
}

// monitor contacts the autograph service and verifies all monitoring signatures
func monitor(conf *configuration, client *http.Client) error {
	log.Println("Retrieving monitoring data from", conf.origAutographURL)
	req, err := http.NewRequest("GET", conf.requestURL, nil)
	if err != nil {
		return fmt.Errorf("unable to create NewRequest to the monitor endpoint: %w", err)
	}

	// For client requests, setting this field prevents re-use of
	// TCP connections between requests to the same hosts, as if
	// Transport.DisableKeepAlives were set.
	req.Close = true

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", makeAuthHeader(req, "monitor", conf.monitoringKey))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request to monitor endpoint failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error reading failed monitor response body (original HTTP status was %s): %w", resp.Status, err)
		}
		return fmt.Errorf("monitor request failed with status %s and body: %s", resp.Status, body)
	}

	x5uClient := defaultX5UClient()

	dec := json.NewDecoder(resp.Body)
	failed := false
	var failures []error
	for {
		var response formats.SignatureResponse
		if err := dec.Decode(&response); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("unable to parse the streaming SignatureReponse JSON: %w", err)
		}

		var err error
		switch response.Type {
		case contentsignature.Type:
			log.Printf("Verifying content signature from signer %q", response.SignerID)
			if response.X5U == "" {
				// The X5U is optional for contentsignature signers.
				err = contentsignature.VerifyResponse([]byte(inputdata), response)
			} else {
				err = verifyContentSignature(x5uClient, conf.notifier, conf.rootHashes, contentSignatureIgnoredLeafCertCNs, response, []byte(inputdata))
			}
		case contentsignaturepki.Type:
			log.Printf("Verifying content signature pki from signer %q", response.SignerID)
			err = verifyContentSignature(x5uClient, conf.notifier, conf.rootHashes, contentSignatureIgnoredLeafCertCNs, response, []byte(inputdata))
		case xpi.Type:
			log.Printf("Verifying XPI signature from signer %q", response.SignerID)
			err = verifyXPISignature(response.Signature, conf.truststore, conf.depTruststore)
		case apk2.Type:
			// we don't verify apk2 signatures because they can only be obtained on valid
			// APK files, which is too big to fit in the monitoring logic
			log.Printf("Skipping verification of APK2 signature from signer %q (we can't verify those)", response.SignerID)
			continue
		case mar.Type:
			log.Printf("Verifying MAR signature from signer %q", response.SignerID)
			err = verifyMARSignature(response.Signature, response.PublicKey)
		case genericrsa.Type:
			log.Printf("Verifying RSA signature from signer %q", response.SignerID)
			err = genericrsa.VerifyGenericRsaSignatureResponse([]byte(inputdata), response)
		case gpg2.Type:
			// we don't verify pgp signatures because that requires building a keyring
			// using the public key which is hard to do using the current openpgp package
			log.Printf("Skipping verification of PGP signature from signer %q (we can't verify those)", response.SignerID)
			continue
		default:
			err = fmt.Errorf("unknown signature type %q", response.Type)
		}
		if err != nil {
			failed = true
			log.Printf("Response from signer %q does not pass: %v", response.SignerID, err)
			log.Printf("Response was: %+v", response)
			failures = append(failures, err)
		} else {
			log.Printf("Response from signer %q passes verification", response.SignerID)
		}
	}
	if failed {
		failure := "Errors found during monitoring:"
		for i, fail := range failures {
			failure += fmt.Sprintf("\n%d. %s", i+1, fail.Error())
		}
		return errors.New(failure)
	}
	log.Println("All signature responses passed, monitoring OK")
	return nil
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
