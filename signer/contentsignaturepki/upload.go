package contentsignaturepki

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/errors"
)

// upload takes a string and a filename and puts it at the upload location
// defined in the signer, then returns its URL
func (s *ContentSigner) upload(data, name string) error {
	parsedURL, err := url.Parse(s.chainUploadLocation)
	if err != nil {
		return errors.Wrap(err, "failed to parse chain upload location")
	}
	switch parsedURL.Scheme {
	case "s3":
		return uploadToS3(data, name, parsedURL)
	default:
		return errors.New("unsupported upload scheme " + parsedURL.Scheme)
	}
}

func uploadToS3(data, name string, target *url.URL) error {
	sess := session.Must(session.NewSession())
	uploader := s3manager.NewUploader(sess)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket:             aws.String(target.Host),
		Key:                aws.String(target.Path + name),
		ACL:                aws.String("public-read"),
		Body:               strings.NewReader(data),
		ContentType:        aws.String("binary/octet-stream"),
		ContentDisposition: aws.String("attachment"),
	})
	return err
}

func verifyX5U(x5u string) error {
	// retrieve file from upload location and verify chain
	resp, err := http.Get(x5u)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve x5u")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("failed to retrieve x5u from %s: %s", x5u, resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to parse x5u body")
	}
	// verify the chain. the first cert is the end entity, then the intermediate and the root
	block, rest := pem.Decode(body)
	ee, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse ee certificate from chain")
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rest)
	if !ok {
		return errors.New("failed to parse issuer chain")
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: roots,
		KeyUsages:     ee.ExtKeyUsage,
	}
	_, err = ee.Verify(opts)
	if err != nil {
		return errors.Wrap(err, "failed to verify certificate chain")
	}

	return nil
}