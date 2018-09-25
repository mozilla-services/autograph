package cose

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var CompressionTestCases = []struct {
	name         string
	input        map[interface{}]interface{}
	intermediate map[interface{}]interface{}
	roundtrip    map[interface{}]interface{}
}{
	{
		"all empty",
		map[interface{}]interface{}{},
		map[interface{}]interface{}{},
		map[interface{}]interface{}{},
	},
	{
		"all keys",
		map[interface{}]interface{}{
			"counter signature": []int{1, 2, -3},
			"Partial IV":        "foo",
			"alg":               true,
			"IV":                nil,
			"content type":      false,
			"kid":               -1,
			"crit":              true,
		},
		map[interface{}]interface{}{
			3: false,
			1: true,
			2: true,
			4: -1,
			5: nil,
			6: "foo",
			7: []int{1, 2, -3},
		},
		map[interface{}]interface{}{
			"counter signature": []int{1, 2, -3},
			"Partial IV":        "foo",
			"alg":               true,
			"IV":                nil,
			"content type":      false,
			"kid":               -1,
			"crit":              true,
		},
	},
	{
		"unknown key",
		map[interface{}]interface{}{
			"unknown": -1,
		},
		map[interface{}]interface{}{
			"unknown": -1,
		},
		map[interface{}]interface{}{
			"unknown": -1,
		},
	},
	{
		"known key wrong case \"ALG\"",
		map[interface{}]interface{}{
			"ALG": 1,
		},
		map[interface{}]interface{}{
			"ALG": 1,
		},
		map[interface{}]interface{}{
			"ALG": 1,
		},
	},
	{
		"supported alg value \"ES256\" compressed",
		map[interface{}]interface{}{
			"alg": "ES256",
		},
		map[interface{}]interface{}{
			1: -7,
		},
		map[interface{}]interface{}{
			"alg": "ES256",
		},
	},
	{
		"supported alg value \"PS256\" compressed",
		map[interface{}]interface{}{
			"alg": "PS256",
		},
		map[interface{}]interface{}{
			1: -37,
		},
		map[interface{}]interface{}{
			"alg": "PS256",
		},
	},
	{
		"converts int64 to int",
		map[interface{}]interface{}{
			int64(1): int64(-37),
		},
		map[interface{}]interface{}{
			1: -37,
		},
		map[interface{}]interface{}{
			"alg": "PS256",
		},
	},
}

func TestHeaderCompressionRoundTrip(t *testing.T) {
	for _, testCase := range CompressionTestCases {
		assert := assert.New(t)

		compressed := CompressHeaders(testCase.input)
		assert.Equal(
			testCase.intermediate,
			compressed,
			fmt.Sprintf("%s: header compression failed", testCase.name))

		assert.Equal(
			testCase.roundtrip,
			DecompressHeaders(compressed),
			fmt.Sprintf("%s: header compression-decompression roundtrip failed", testCase.name))
	}
}

func TestHeaderCompressionDoesNotDecompressUnknownTag(t *testing.T) {
	assert := assert.New(t)

	compressed := map[interface{}]interface{}{
		777: 1,
	}
	assert.Equal(
		compressed,
		DecompressHeaders(compressed),
		"header decompression modifies unknown tag")
}

func TestGetAlgPanics(t *testing.T) {
	assert := assert.New(t)

	var algName = "FOOOO"
	assert.Panics(func () { getAlgByNameOrPanic(algName) })
}

func TestGetCommonHeaderTagOrPanicPanics(t *testing.T) {
	assert := assert.New(t)

	var label = "FOOOO"
	assert.Panics(func () { GetCommonHeaderTagOrPanic(label) })
}

func TestGetAlgWithString(t *testing.T) {
	assert := assert.New(t)

	var h *Headers = nil
	alg, err := getAlg(h)
	assert.Nil(alg)
	assert.NotNil(err)
	assert.Equal("Cannot getAlg on nil Headers", err.Error())

	h = &Headers{}
	h.Protected = map[interface{}]interface{}{
		"alg": "ROT13",
	}
	alg, err = getAlg(h)
	assert.Nil(alg)
	assert.NotNil(err)
	assert.Equal(err.Error(), "Algorithm named ROT13 not found")

	h.Protected["alg"] = "ES256"
	alg, err = getAlg(h)
	assert.NotNil(alg)
	assert.Nil(err)
	assert.Equal(alg.Name, "ES256")
}

func TestFindDuplicateHeaderWithNilHeaders(t *testing.T) {
	assert := assert.New(t)

	var h *Headers = nil
	assert.Nil(FindDuplicateHeader(h))
}

func TestHeaderEncodeErrors(t *testing.T) {
	assert := assert.New(t)

	var h *Headers = nil
	assert.Panics(func () { h.EncodeProtected() })

	h = &Headers{
		Protected: map[interface{}]interface{}{
			"alg": -3,
			1: -7,
		},
	}
	assert.Panics(func () { h.EncodeProtected() })
}

func TestHeaderDecodeErrors(t *testing.T) {
	assert := assert.New(t)

	var (
		h *Headers = &Headers{
			Protected: nil,
			Unprotected: nil,
		}
		v []interface{}
		err error
	)
	err = h.Decode(v)
	assert.NotNil(err)
	assert.Equal(err.Error(), "can only decode headers from 2-item array; got 0")

	v = []interface{}{[]byte("\x90"), map[interface{}]interface{}{}}
	err = h.Decode(v)
	assert.NotNil(err)
	assert.Equal(err.Error(), "error CBOR decoding protected header bytes; got <nil>")

	v = []interface{}{[]byte("\x60"), map[interface{}]interface{}{}}
	err = h.Decode(v)
	assert.NotNil(err)
	assert.Equal(err.Error(), "error casting protected to map; got string")

	v = []interface{}{[]byte("\xA1\x02\x26"), -1}
	err = h.Decode(v)
	assert.NotNil(err)
	assert.Equal(err.Error(), "error decoding unprotected header as map[interface {}]interface {}; got int")
}
