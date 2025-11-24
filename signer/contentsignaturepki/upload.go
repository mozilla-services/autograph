package contentsignaturepki

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	csigverifier "github.com/mozilla-services/autograph/verifier/contentsignature"
)

// S3UploadAPI is an interface to accommodate testing
// Adapted from https://aws.github.io/aws-sdk-go-v2/docs/unit-testing/
type S3UploadAPI interface {
	Upload(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error)
}

// upload takes a string and a filename and puts it at the upload location
// defined in the signer, then returns its URL
func (s *ContentSigner) upload(data, name string) error {
	parsedURL, err := url.Parse(s.chainUploadLocation)
	if err != nil {
		return fmt.Errorf("failed to parse chain upload location: %w", err)
	}
	switch parsedURL.Scheme {
	case "s3":
		// Context is a required argument, but in our uses,
		// LoadDefaultConfig pulls the necessary configuration
		// from the environment.
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return fmt.Errorf("failed to load AWS config: %w", err)
		}
		client := s3.NewFromConfig(cfg)
		uploader := manager.NewUploader(client)
		return uploadToS3(uploader, data, name, parsedURL)
	case "file":
		return writeLocalFile(data, name, parsedURL)
	default:
		return fmt.Errorf("unsupported upload scheme %#v", parsedURL.Scheme)
	}
}

func uploadToS3(client S3UploadAPI, data, name string, target *url.URL) error {
	// aws-sdk-go-v2 now includes leading slashes in the key name, where v1 did
	// not. So, to keep this code compatible, we have to trim it.
	keyName := strings.TrimPrefix(path.Join(target.Path, name), "/")
	_, err := client.Upload(context.Background(), &s3.PutObjectInput{
		Bucket:             aws.String(target.Host),
		Key:                aws.String(keyName),
		ACL:                types.ObjectCannedACLPublicRead,
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

	return os.WriteFile(filepath.Join(target.Path, name), []byte(data), 0755)
}

// GetX5U retrieves a chain file of certs from upload location, parses
// and verifies it, then returns a byte slice of the response body and
// a slice of parsed certificates.
func GetX5U(client *http.Client, x5u string) ([]byte, []*x509.Certificate, error) {
	parsedURL, err := url.Parse(x5u)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse chain upload location: %w", err)

	}
	var bodyReader io.ReadCloser
	switch parsedURL.Scheme {
	case "https", "http":
		resp, err := client.Get(x5u)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve x5u from %#v: %w", x5u, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("failed to retrieve x5u from %#v: %s", x5u, resp.Status)
		}
		bodyReader = resp.Body

	case "file":
		bodyReader, err = os.Open(parsedURL.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open x5u file:// at %#v: %w", x5u, err)
		}
		defer bodyReader.Close()
	default:
		return nil, nil, fmt.Errorf("unsupported x5u scheme: %#v", parsedURL.Scheme)
	}

	body, err := io.ReadAll(bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse x5u body from %#v: %w", x5u, err)
	}
	certs, err := csigverifier.ParseChain(body)
	if err != nil {

		return nil, nil, fmt.Errorf("failed to parse x5u : %w", err)
	}
	rootHash := sha2Fingerprint(certs[2])
	err = csigverifier.VerifyChain([]string{rootHash}, certs, time.Now())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify certificate chain: %w", err)
	}
	return body, certs, nil
}

func sha2Fingerprint(cert *x509.Certificate) string {
	return strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(cert.Raw)))
}
