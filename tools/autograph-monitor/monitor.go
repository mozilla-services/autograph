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

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/xpi"
	"go.mozilla.org/hawk"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"
	yaml "gopkg.in/yaml.v2"
)

// a signatureresponse is returned by autograph to a client with
// a signature computed on input data
type signatureresponse struct {
	Ref        string `json:"ref"`
	Type       string `json:"type"`
	Mode       string `json:"mode"`
	SignerID   string `json:"signer_id"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
	SignedFile string `json:"signed_file,omitempty"`
	X5U        string `json:"x5u,omitempty"`
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
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		// we are inside a lambda environment so run as lambda
		lambda.Start(Handler)
	} else {
		err := Handler()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}
}

func Handler() (err error) {
	confdir := "."
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		confdir = os.Getenv("LAMBDA_TASK_ROOT")
	}
	// load the local configuration file
	conf, err = loadConf(confdir + "/monitor.autograph.yaml")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %v", err)
	}

	log.Println("Retrieving monitoring data from", conf.URL)
	req, err := http.NewRequest("GET", conf.URL+"__monitor__", nil)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", makeAuthHeader(req, "monitor", conf.MonitoringKey))
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Request failed with %s: %s", resp.Status, body)
	}

	// verify that we got a proper signature response, with valid signatures
	var responses []signatureresponse
	err = json.Unmarshal(body, &responses)
	if err != nil {
		return
	}
	failed := false
	var failures []error
	for i, response := range responses {
		switch response.Type {
		case contentsignature.Type:
			log.Printf("Verifying content signature from signer %q", response.SignerID)
			err = verifyContentSignature(response)
		case xpi.Type:
			log.Printf("Verifying XPI signature from signer %q", response.SignerID)
			err = verifyXPISignature(response.Signature, conf.truststore)
		case apk.Type:
			log.Printf("Verifying APK signature from signer %q", response.SignerID)
			err = verifyAPKSignature(response.Signature)
		default:
			err = fmt.Errorf("unknown signature type %q", response.Type)
		}
		if err != nil {
			failed = true
			log.Printf("Response %d from signer %q does not pass: %v", i, response.SignerID, err)
			log.Printf("Response was: %+v", response)
			failures = append(failures, err)
		} else {
			log.Printf("Response %d from signer %q passes verification", i, response.SignerID)
		}
	}
	if failed {
		failure := "Errors found during monitoring:"
		for i, fail := range failures {
			failure += fmt.Sprintf("\n%d. %s", i+1, fail.Error())
		}
		return fmt.Errorf(failure)
	}
	log.Println("All signature responses passed, monitoring OK")
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

// send a message to a predefined sns topic
func sendSoftNotification(format string, a ...interface{}) error {
	svc := sns.New(session.New())
	params := &sns.PublishInput{
		Message:  aws.String(fmt.Sprintf(format, a...)),
		TopicArn: aws.String(os.Getenv("AUTOGRAPH_SOFT_NOTIFICATION_SNS")),
	}
	_, err := svc.Publish(params)
	if err != nil {
		return err
	}
	log.Printf("Soft notification send to %q with body: %s", os.Getenv("AUTOGRAPH_SOFT_NOTIFICATION_SNS"), params.Message)
	return nil
}
