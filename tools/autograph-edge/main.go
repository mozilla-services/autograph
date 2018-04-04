package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/mozilla-services/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"
)

var (
	errInvalidToken              = errors.New("invalid authorization token")
	errInvalidMethod             = errors.New("only POST requests are supported")
	errMissingBody               = errors.New("missing request body")
	errAutographBadStatusCode    = errors.New("failed to retrieve signature from autograph")
	errAutographBadResponseCount = errors.New("received an invalid number of responses from autograph")
	errAutographEmptyResponse    = errors.New("autograph returned an invalid empty response")

	conf configuration
)

type configuration struct {
	URL            string
	Authorizations []authorization
}

type authorization struct {
	Token   string
	Signer  string
	User    string
	Key     string
	AddonID string
}

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph-edge")

	// in lambda, load the config here to keep it in the runtime
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		log.Info("loading configuration from " + os.Getenv("LAMBDA_TASK_ROOT") + "/autograph-edge.yaml")
		err := conf.loadFromFile(os.Getenv("LAMBDA_TASK_ROOT") + "/autograph-edge.yaml")
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		lambda.Start(Handler)
	} else {
		var cfgFile, token, filePath string
		flag.StringVar(&cfgFile, "c", "autograph-edge.yaml", "Path to configuration file")
		flag.StringVar(&token, "a", "dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd", "auth token")
		flag.StringVar(&filePath, "f", "/path/to/file", "path to file to sign")
		flag.Parse()

		body, err := ioutil.ReadFile(filePath)
		if err != nil {
			log.Fatal(err)
		}

		err = conf.loadFromFile(cfgFile)
		if err != nil {
			log.Fatal(err)
		}

		headers := make(map[string]string)
		headers["Authorization"] = token
		resp, err := Handler(events.APIGatewayProxyRequest{
			HTTPMethod: http.MethodPost,
			Body:       base64.StdEncoding.EncodeToString(body),
			Headers:    headers,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			log.Fatal("signing failed")
		}
		signedBody, err := base64.StdEncoding.DecodeString(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		ioutil.WriteFile(filePath, signedBody, 06400)
		log.Println("signed file written to", filePath)
	}
}

// Handler receives requests from AWS API Gateway and processes them. The input body must
// contain a base64 encoded file to sign, and the response body contains a base64 encoded
// signed file. The Authorization header of the http request must contain a valid token.
func Handler(r events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	log.WithFields(log.Fields{
		"remoteAddressChain": "[" + r.Headers["X-Forwarded-For"] + "]",
		"method":             r.HTTPMethod,
		"url":                r.Path,
		"content-type":       r.Headers["content-type"],
		"rid":                r.RequestContext.RequestID,
	}).Info("request")

	// some sanity checking on the request
	if r.HTTPMethod != http.MethodPost {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error("invalid method")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusMethodNotAllowed, Body: errInvalidMethod.Error()}, errInvalidMethod
	}
	if len(r.Headers["Authorization"]) < 60 {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error("missing authorization header")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized, Body: errInvalidToken.Error()}, errInvalidToken
	}
	if len(r.Body) < 1 {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error("missing request body")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: errMissingBody.Error()}, errMissingBody
	}

	// verify auth token
	log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Info("checking authorization token")
	auth, err := authorize(r.Headers["Authorization"])
	if err != nil {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error(err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized, Body: err.Error()}, err
	}
	log.WithFields(log.Fields{
		"rid":  r.RequestContext.RequestID,
		"user": auth.User,
	}).Info("authorization succeeded")

	// decode the base64 body of the file
	decodedBody, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error(err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: err.Error()}, err
	}

	// let's get this file signed!
	log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Info("calling autograph")
	signedBody, err := callAutograph(auth, decodedBody)
	if err != nil {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error(err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError, Body: err.Error()}, err
	}

	log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Info("returning signed data")
	return events.APIGatewayProxyResponse{
		Body:       base64.StdEncoding.EncodeToString(signedBody),
		StatusCode: http.StatusOK,
	}, nil

}

// loadFromFile reads a configuration from a local file
func (c *configuration) loadFromFile(path string) error {
	var confData []byte
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
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
			return errors.Wrap(err, "failed to load sops encrypted configuration")
		}
	}
	err = yaml.Unmarshal(confData, &c)
	if err != nil {
		return err
	}
	return nil
}

func authorize(authHeader string) (auth authorization, err error) {
	for _, auth := range conf.Authorizations {
		if authHeader == auth.Token {
			return auth, nil
		}
	}
	return authorization{}, errInvalidToken
}
