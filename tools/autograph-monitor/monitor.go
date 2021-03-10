package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/apk2"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/contentsignaturepki"
	"go.mozilla.org/autograph/signer/genericrsa"
	"go.mozilla.org/autograph/signer/gpg2"
	"go.mozilla.org/autograph/signer/mar"
	"go.mozilla.org/autograph/signer/pgp"
	"go.mozilla.org/autograph/signer/rsapss"
	"go.mozilla.org/autograph/signer/xpi"
	"go.mozilla.org/hawk"
)

type configuration struct {
	url           string
	monitoringKey string
	env           string
	rootHash      string
	truststore    *x509.CertPool

	// hash and keystore for verifying XPI dep signers
	depRootHash   string
	depTruststore *x509.CertPool

	// hash and keystore for verifying ContentSignature responses
	// when XPI and ContentSignature branches of the code signing
	// PKI use different roots
	contentSignatureRootHash   string
	contentSignatureTruststore *x509.CertPool
}

var conf configuration

const inputdata string = "AUTOGRAPH MONITORING"


func main() {
	conf.url = os.Getenv("AUTOGRAPH_URL")
	if conf.url == "" {
		log.Fatal("AUTOGRAPH_URL must be set to the base url of the autograph service")
	}
	conf.monitoringKey = os.Getenv("AUTOGRAPH_KEY")
	if conf.monitoringKey == "" {
		log.Fatal("AUTOGRAPH_KEY must be set to the api monitoring key")
	}

	// configure monitor to check responses against Fx stage or
	// prod or autograph dev code signing PKI roots and CA root
	// certs defined in constants.go
	conf.env = os.Getenv("AUTOGRAPH_ENV")
	switch conf.env {
	case "stage":
		conf.rootHash = firefoxPkiStageRootHash
		conf.truststore = x509.NewCertPool()
		conf.truststore.AppendCertsFromPEM([]byte(firefoxPkiStageRoot))
		conf.contentSignatureRootHash = firefoxPkiContentSignatureStageRootHash
		conf.contentSignatureTruststore = x509.NewCertPool()
		conf.contentSignatureTruststore.AppendCertsFromPEM([]byte(firefoxPkiContentSignatureStageRoot))
		conf.depRootHash = ""
		conf.depTruststore = nil
	case "prod":
		conf.rootHash = firefoxPkiProdRootHash
		conf.truststore = x509.NewCertPool()
		conf.truststore.AppendCertsFromPEM([]byte(firefoxPkiProdRoot))
		conf.contentSignatureRootHash = firefoxPkiProdRootHash
		conf.contentSignatureTruststore = conf.truststore
		conf.depRootHash = firefoxPkiStageRootHash
		conf.depTruststore = x509.NewCertPool()
		conf.depTruststore.AppendCertsFromPEM([]byte(firefoxPkiStageRoot))
	default:
		conf.rootHash = autographDevRootHash
		conf.truststore = nil
		conf.contentSignatureRootHash = autographDevRootHash
		conf.contentSignatureTruststore = nil
		conf.depRootHash = ""
		conf.depTruststore = nil
	}
	if os.Getenv("AUTOGRAPH_ROOT_HASH") != "" {
		conf.rootHash = os.Getenv("AUTOGRAPH_ROOT_HASH")
		conf.contentSignatureRootHash = conf.rootHash
	}
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		// we are inside a lambda environment so run as lambda
		lambda.Start(Handler)
	} else {
		err := Handler()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

// Handler is a wrapper around monitor() that performs garbage collection
// before returning
func Handler() (err error) {
	defer func() {
		// force gc run
		// https://bugzilla.mozilla.org/show_bug.cgi?id=1621133
		t1 := time.Now()
		runtime.GC()
		log.Println("Garbage collected in", time.Now().Sub(t1))
	}()
	return monitor()
}

// monitor contacts the autograph service and verifies all monitoring signatures
func monitor() (err error) {
	log.Println("Retrieving monitoring data from", conf.url)
	req, err := http.NewRequest("GET", conf.url+"__monitor__", nil)
	if err != nil {
		return
	}

	// For client requests, setting this field prevents re-use of
	// TCP connections between requests to the same hosts, as if
	// Transport.DisableKeepAlives were set.
	req.Close = true

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", makeAuthHeader(req, "monitor", conf.monitoringKey))
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil || resp == nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Request failed with %s: %s", resp.Status, resp.Body)
	}

	dec := json.NewDecoder(resp.Body)
	failed := false
	var failures []error
	for {
		var response formats.SignatureResponse
		if err := dec.Decode(&response); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}
		switch response.Type {
		case contentsignature.Type:
			log.Printf("Verifying content signature from signer %q", response.SignerID)
			err = verifyContentSignature(conf.contentSignatureRootHash, response)
		case contentsignaturepki.Type:
			log.Printf("Verifying content signature pki from signer %q", response.SignerID)
			err = verifyContentSignature(conf.contentSignatureRootHash, response)
		case xpi.Type:
			log.Printf("Verifying XPI signature from signer %q", response.SignerID)
			err = verifyXPISignature(response.Signature)
		case apk.Type:
			log.Printf("Verifying APK signature from signer %q", response.SignerID)
			err = verifyAPKSignature(response.Signature)
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
		case rsapss.Type:
			log.Printf("Verifying RSA-PSS signature from signer %q", response.SignerID)
			err = verifyRsapssSignature(response.Signature, response.PublicKey)
		case pgp.Type, gpg2.Type:
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
		return fmt.Errorf(failure)
	}
	log.Println("All signature responses passed, monitoring OK")
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
func sendSoftNotification(id string, format string, a ...interface{}) error {
	if os.Getenv("LAMBDA_TASK_ROOT") == "" || os.Getenv("AUTOGRAPH_SOFT_NOTIFICATION_SNS") == "" {
		// We're not running in lambda or the conf isnt ready so don't try to publish to SQS
		log.Printf("soft notification ID %s: %s", id, fmt.Sprintf(format, a...))
		return nil
	}

	svc := sns.New(session.New())
	params := &sns.PublishInput{
		Message:  aws.String(fmt.Sprintf(format, a...)),
		TopicArn: aws.String(os.Getenv("AUTOGRAPH_SOFT_NOTIFICATION_SNS")),
	}
	_, err := svc.Publish(params)
	if err != nil {
		return err
	}
	log.Printf("Soft notification send to %q with body: %s", os.Getenv("AUTOGRAPH_SOFT_NOTIFICATION_SNS"), *params.Message)
	return nil
}
