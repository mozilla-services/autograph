package contentsignaturepki

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	csigverifier "github.com/mozilla-services/autograph/verifier/contentsignature"
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

// GetX5U retrieves a chain file of certs from upload location, parses
// and verifies it, then returns a byte slice of the response body and
// a slice of parsed certificates.
func GetX5U(x5u string) (body []byte, certs []*x509.Certificate, err error) {
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
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("failed to parse x5u body: %w", err)
		return
	}
	certs, err = csigverifier.ParseChain(body)
	if err != nil {
		err = fmt.Errorf("failed to parse x5u : %w", err)
		return
	}
	rootHash := sha2Fingerprint(certs[2])
	err = csigverifier.VerifyChain(rootHash, certs, time.Now())
	if err != nil {
		err = fmt.Errorf("failed to verify certificate chain: %w", err)
		return
	}
	return
}

func sha2Fingerprint(cert *x509.Certificate) string {
	return strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(cert.Raw)))
}
