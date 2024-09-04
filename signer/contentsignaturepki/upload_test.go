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
		testName            string
		client              func(t *testing.T) S3UploadAPI
		data                string
		name                string
		chainUploadLocation string
		expectErr           bool
	}{
		{
			testName: "successful_upload",
			client: func(t *testing.T) S3UploadAPI {
				return mockUploadAPI(func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error) {
					expectedBucket := "foo.bar"
					if *input.Bucket != expectedBucket {
						t.Errorf("bucket: want %#v, got %#v", expectedBucket, *input.Bucket)
					}
					if *input.Key != "somestuff/successful_chain" {
						t.Errorf("key: want \"somestuff/successful_chain\", got %#v", *input.Key)
					}
					return &manager.UploadOutput{}, nil
				})
			},
			data:                "foo",
			name:                "successful_chain",
			chainUploadLocation: "s3://foo.bar/somestuff/",
			expectErr:           false,
		},
		{
			testName: "successful_upload_with_missing_slash",
			client: func(t *testing.T) S3UploadAPI {
				return mockUploadAPI(func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error) {
					expectedBucket := "foo.bar"
					if *input.Bucket != expectedBucket {
						t.Errorf("bucket: want %#v, got %#v", expectedBucket, *input.Bucket)
					}
					expectedKey := "somestuff/successful_chain"
					if *input.Key != expectedKey {
						t.Errorf("key: want %#v, got %#v", expectedKey, *input.Key)
					}
					return &manager.UploadOutput{}, nil
				})
			},
			data:                "foo",
			name:                "successful_chain",
			chainUploadLocation: "s3://foo.bar/somestuff",
			expectErr:           false,
		},
		{
			testName: "failed_upload",
			client: func(t *testing.T) S3UploadAPI {
				return mockUploadAPI(func(ctx context.Context, input *s3.PutObjectInput, opts ...func(*manager.Uploader)) (*manager.UploadOutput, error) {
					expectedBucket := "foo.quux"
					if *input.Bucket != expectedBucket {
						t.Errorf("bucket: want %#v, got %#v", expectedBucket, *input.Bucket)
					}
					expectedKey := "something/will_fail_chain"
					if *input.Key != expectedKey {
						t.Errorf("key: want %#v, got %#v", expectedKey, *input.Key)
					}
					return nil, errors.New("upload failed")
				})
			},
			data:                "foo",
			name:                "will_fail_chain",
			chainUploadLocation: "s3://foo.quux/something/",
			expectErr:           true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.testName, func(t *testing.T) {
			t.Parallel()
			url, err := url.Parse(tt.chainUploadLocation)
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
