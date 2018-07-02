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


func TestIsValidCOSESignatureErrs(t *testing.T) {
	t.Parallel()

	cases := []struct{
		input  *cose.Signature
		results []string
	}{
		{
			input: nil,
			results: []string{"xpi: cannot validate nil COSE Signature"},
		},
		{
			input: &cose.Signature{},
			results: []string{"xpi: got unexpected COSE Signature headers: xpi: cannot compare nil COSE headers"},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{"foo": 2},
				},
			},
			results: []string{"xpi: got unexpected COSE Signature headers: xpi: unexpected non-empty Unprotected headers got: map[foo:2]"},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: unexpected Protected headers got: map[] expected: map[1:<nil> 4:<nil>]",
				"xpi: got unexpected COSE Signature headers: xpi: unexpected Protected headers got: map[] expected: map[4:<nil> 1:<nil>]",			},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						"foo": 2,
						"bar": 1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: missing expected alg in Protected Headers",
			},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: 2,
						"bar": 1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: alg 2 is not supported",
			},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: cose.ES256.Value,
						"bar": 1,
					},
				},
			},
			results: []string{
				"xpi: got unexpected COSE Signature headers: xpi: missing expected kid in Protected Headers",
			},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: cose.ES256.Value,
						kidHeaderValue: "foo",
					},
				},
			},
			results: []string{
				"xpi: COSE Signature kid value is not a byte array",
			},
		},
		{
			input: &cose.Signature{
				Headers: &cose.Headers{
					Protected: map[interface{}]interface{}{
						algHeaderValue: cose.ES256.Value,
						kidHeaderValue: []byte("OK"),
					},
				},
			},
			results: []string{
				"xpi: failed to parse X509 EE certificate from COSE Signature: asn1: structure error: tags don't match (16 vs {class:1 tag:15 length:75 isCompound:false}) {optional:false explicit:false application:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} certificate @2",
			},
		},
	}

	for _, testcase := range cases {
		_, err := isValidCOSESignature(testcase.input)
		anyMatches := false
		for _, result := range testcase.results {
			if err.Error() == result {
				anyMatches = true
			}
		}
		if !anyMatches {
			t.Fatalf("isValidCOSESignature returned '%v'", err)
		}
	}
}

func TestIsValidCOSEMessageErrs(t *testing.T) {
	t.Parallel()

	cases := []struct{
		input  *cose.SignMessage
		results []string
	}{
		{
			input: nil,
			results: []string{"xpi: cannot validate nil COSE SignMessage"},
		},
		{
			input: &cose.SignMessage{Payload: []byte("not nil!")},
			results: []string{"xpi: expected SignMessage payload to be nil, but got [110 111 116 32 110 105 108 33]"},
		},
		{
			input: &cose.SignMessage{Payload: nil},
			results: []string{"xpi: got unexpected COSE SignMessage headers: xpi: cannot compare nil COSE headers"},
		},
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: nil,
					},
				},
			},
			results: []string{"xpi: expected SignMessage Protected Headers kid value to be an array got <nil> with type <nil>"},
		},
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: []interface{}{
							nil,
						},
					},
				},
			},
			results: []string{"xpi: expected SignMessage Protected Headers kid value 0 to be a byte slice got <nil> with type <nil>"},
		},
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: []interface{}{
							[]byte("not a cert"),
						},
					},
				},
			},
			results: []string{"xpi: SignMessage Signature Protected Headers kid value 0 does not decode to a parseable X509 cert: asn1: structure error: tags don't match (16 vs {class:1 tag:14 length:111 isCompound:true}) {optional:false explicit:false application:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} certificate @2"},
		},
		{
			input: &cose.SignMessage{
				Payload: nil,
				Headers: &cose.Headers{
					Unprotected: map[interface{}]interface{}{},
					Protected: map[interface{}]interface{}{
						kidHeaderValue: []interface{}{},
					},
				},
				Signatures: []cose.Signature{
					cose.Signature{},
				},
			},
			results: []string{"xpi: cose signature 0 is invalid: xpi: got unexpected COSE Signature headers: xpi: cannot compare nil COSE headers"},
		},
	}

	for _, testcase := range cases {
		_, _, err := isValidCOSEMessage(testcase.input)
		anyMatches := false
		for _, result := range testcase.results {
			if err.Error() == result {
				anyMatches = true
			}
		}
		if !anyMatches {
			t.Fatalf("isValidCOSEMessage returned '%v'", err)
		}
	}
}
