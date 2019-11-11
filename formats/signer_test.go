package formats

import (
	"testing"
)

func TestSignerIDValidation(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		signerID    string
		shouldError bool
	}{
		{"", true},
		{"!!!", true},
		{"-", false},
		{"_", false},
		{"ooook", false},
	}
	for i, testcase := range testcases {
		err := ValidateSignerID(testcase.signerID)
		if testcase.shouldError && err == nil {
			t.Fatalf("test %d did not fail for %q", i, testcase.signerID)
		} else if !testcase.shouldError && err != nil {
			t.Fatalf("test %d failed for %q with %q", i, testcase.signerID, err)
		}
	}
}
