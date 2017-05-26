package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/xpi"
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
	RootCert      string `yaml:"rootcert"`
	truststore    *x509.CertPool
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Request failed with %s: %s", resp.Status, body)
	}

	// verify that we got a proper signature response, with valid signatures
	var responses []signatureresponse
	err = json.Unmarshal(body, &responses)
	if err != nil {
		log.Fatal(err)
	}
	failed := false
	for i, response := range responses {
		switch response.Type {
		case contentsignature.Type:
			err = verifyContentSignature(response.Signature, response.PublicKey)
		case xpi.Type:
			err = verifyXPISignature(response.Signature, conf.truststore)
		default:
			failed = true
			log.Printf("unknown signature type %q", response.Type)
		}
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
	confData, err := decrypt.Data(data, "yaml")
	if err != nil {
		if err.Error() == sops.MetadataNotFound.Error() {
			// not an encrypted file
			confData = data
		} else {
			return
		}
	}
	err = yaml.Unmarshal(confData, &cfg)
	if cfg.RootCert != "" {
		cfg.truststore = x509.NewCertPool()
		cfg.truststore.AppendCertsFromPEM([]byte(cfg.RootCert))
	}
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
