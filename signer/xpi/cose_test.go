package xpi

import (
	"testing"

	"go.mozilla.org/cose"
)

func TestStringToCOSEAlg(t *testing.T) {
	t.Parallel()

	cases := []struct{
		input string
		result *cose.Algorithm
	}{
		{input: "ES256", result: cose.ES256},
		{input: "es384", result: cose.ES384},
		{input: "Es512", result: cose.ES512},
		{input: "PS256", result: cose.PS256},
		{input: " PS256", result: nil},
		{input: "PS256!", result: nil},
	}

	for _, testcase := range cases {
		result := stringToCOSEAlg(testcase.input)
		if result != testcase.result {
			t.Fatalf("stringToCOSEAlg returned %v but expected %v", result, testcase.result)
		}
	}
}
