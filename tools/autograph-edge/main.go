package main

import (
	"encoding/base64"
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
	ErrInvalidToken              = errors.New("invalid authorization token")
	ErrInvalidMethod             = errors.New("only POST requests are supported")
	ErrMissingBody               = errors.New("missing request body")
	ErrAutographBadStatusCode    = errors.New("failed to retrieve signature from autograph")
	ErrAutographBadResponseCount = errors.New("received an invalid number of responses from autograph")
	ErrAutographEmptyResponse    = errors.New("autograph returned an invalid empty response")

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

	// load the config
	log.Info("loading configuration from " + os.Getenv("LAMBDA_TASK_ROOT") + "/autograph-edge.yaml")
	err := conf.loadFromFile(os.Getenv("LAMBDA_TASK_ROOT") + "/autograph-edge.yaml")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	if os.Getenv("LAMBDA_TASK_ROOT") != "" {
		lambda.Start(Handler)
	} else {
		resp, err := Handler(events.APIGatewayProxyRequest{Body: os.Args[1]})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		log.Printf("%+v", resp)
	}
}

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
		return events.APIGatewayProxyResponse{StatusCode: http.StatusMethodNotAllowed, Body: ErrInvalidMethod.Error()}, ErrInvalidMethod
	}
	if len(r.Headers["Authorization"]) < 60 {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error("missing authorization header")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized, Body: ErrInvalidToken.Error()}, ErrInvalidToken
	}
	if len(r.Body) < 1 {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error("missing request body")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: ErrMissingBody.Error()}, ErrMissingBody
	}

	decodedBody, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		log.WithFields(log.Fields{"rid": r.RequestContext.RequestID}).Error(err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: err.Error()}, err
	}

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
	return authorization{}, ErrInvalidToken
}
