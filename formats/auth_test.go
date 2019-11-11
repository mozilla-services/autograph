package formats

import (
	"testing"
)

func TestAuthValidation(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		auth        Authorization
		shouldError bool
	}{
		{
			Authorization{
				ID:      "ok-signer_",
				Key:     "2607c565942e7f791d054c622f26c5dfcbbbc914415c09b314e2fbe9dfd7d26c",
				Signers: []string{"signer-1"},
			},
			false,
		},
		{
			Authorization{
				ID:      "ok-signer_",
				Key:     "2607c565942e7f791d054c622f26c5dfcbbbc914415c09b314e2fbe9dfd7d26c",
				Signers: []string{"signer!!!"},
			},
			true,
		},
		{
			Authorization{
				ID:      "!",
				Key:     "2607c565942e7f791d054c622f26c5dfcbbbc914415c09b314e2fbe9dfd7d26c",
				Signers: []string{},
			},
			true,
		},
		{
			Authorization{
				ID:      "-signer",
				Key:     "2607c565942e7f791d054c622f26c5dfcbbbc914415c09b314e2fbe9dfd7d26c",
				Signers: []string{},
			},
			true,
		},
		{
			Authorization{
				ID:      "_signer",
				Key:     "2607c565942e7f791d054c622f26c5dfcbbbc914415c09b314e2fbe9dfd7d26c",
				Signers: []string{},
			},
			true,
		},
		{
			Authorization{
				ID:      "",
				Key:     "2607c565942e7f791d054c622f26c5dfcbbbc914415c09b314e2fbe9dfd7d26c",
				Signers: []string{},
			},
			true,
		},
		{
			Authorization{
				ID:      "ok-signer",
				Key:     "",
				Signers: []string{},
			},
			true,
		},
	}
	for i, testcase := range testcases {
		err := testcase.auth.Validate()
		if testcase.shouldError && err == nil {
			t.Fatalf("test %d did not fail for %q", i, testcase.auth)
		}
		if !testcase.shouldError && err != nil {
			t.Fatalf("test %d failed for %q with %q", i, testcase.auth, err)
		}
	}
}
