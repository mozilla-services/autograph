package contentsignaturepki

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Mocks adapted from https://aws.github.io/aws-sdk-go-v2/docs/unit-testing/
type mockUploadAPI func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error)

func (m mockUploadAPI) Upload(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error) {
	return m(ctx, input, opts...)
}

func TestUploadToS3(t *testing.T) {
	cases := []struct {
		client    func(t *testing.T) S3UploadAPI
		data      string
		name      string
		target    string
		expectErr bool
	}{
		{
			client: func(t *testing.T) S3UploadAPI {
				return mockUploadAPI(func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error) {
					t.Helper()
					return &manager.UploadOutput{}, nil
				})
			},
			data:      "foo",
			name:      "successful_upload",
			target:    "https://foo.bar",
			expectErr: false,
		},
		{
			client: func(t *testing.T) S3UploadAPI {
				return mockUploadAPI(func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error) {
					t.Helper()
					return nil, errors.New("upload failed")
				})
			},
			data:      "foo",
			name:      "failed_upload",
			target:    "https://foo.bar",
			expectErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			url, err := url.Parse(tt.target)
			if err != nil {
				t.Fatalf("error parsing test url: %v", err)
			}

			err = uploadToS3(tt.client(t), tt.data, tt.name, url)

			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error from uploadToS3 but did not get one")
				}
			} else {
				if err != nil {
					t.Fatalf("got unexpected error: %v", err)
				}
			}
		})
	}
}
