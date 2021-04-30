package contentsignaturepki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
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
		return fmt.Errorf("failed to parse chain upload location: %w", err)
	}
	switch parsedURL.Scheme {
	case "s3":
		return uploadToS3(data, name, parsedURL)
	case "file":
		return writeLocalFile(data, name, parsedURL)
	default:
		return fmt.Errorf("unsupported upload scheme " + parsedURL.Scheme)
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

func writeLocalFile(data, name string, target *url.URL) error {
	// upload dir may not exist yet
	_, err := os.Stat(target.Path)
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			// create the target directory
			err = os.MkdirAll(target.Path, 0755)
			if err != nil {
				return fmt.Errorf("failed to make directory: %w", err)
			}
		} else {
			return err
		}
	}
	// write the file into the target dir
	return ioutil.WriteFile(target.Path+name, []byte(data), 0755)
}

// GetX5U retrieves a chain of certs from upload location, parses and verifies it,
// then returns the slice of parsed certificates.
func GetX5U(x5u string) (certs []*x509.Certificate, err error) {
	parsedURL, err := url.Parse(x5u)
	if err != nil {
		err = fmt.Errorf("failed to parse chain upload location: %w", err)
		return
	}
	c := &http.Client{}
	if parsedURL.Scheme == "file" {
		t := &http.Transport{}
		t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
		c.Transport = t
	}
	resp, err := c.Get(x5u)
	if err != nil {
		err = fmt.Errorf("failed to retrieve x5u: %w", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("failed to retrieve x5u from %s: %s", x5u, resp.Status)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("failed to parse x5u body: %w", err)
		return
	}
	// verify the chain
	// the first cert is the end entity, then the intermediate and the root
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		err = fmt.Errorf("failed to PEM decode ee certificate from chain: %w", err)
		return
	}
	ee, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse ee certificate from chain: %w", err)
		return
	}
	certs = append(certs, ee)

	// the second cert is the intermediate
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		err = fmt.Errorf("failed to PEM decode intermediate certificate from chain: %w", err)
		return
	}
	inter, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse intermediate issuer certificate from chain: %w", err)
		return
	}
	inters := x509.NewCertPool()
	inters.AddCert(inter)
	certs = append(certs, inter)

	// the third and last cert is the root
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		err = fmt.Errorf("failed to PEM decode root certificate from chain: %w", err)
		return
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = fmt.Errorf("failed to parse root certificate from chain: %w", err)
		return
	}
	if len(rest) != 0 {
		err = fmt.Errorf("trailing data after root certificate in chain")
		return
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	certs = append(certs, root)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err = ee.Verify(opts)
	if err != nil {
		err = fmt.Errorf("failed to verify certificate chain: %w", err)
		return
	}
	return
}
