package cose

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func WGExampleSignsAndVerifies(t *testing.T, example WGExample) {
	assert := assert.New(t)
	privateKey := LoadPrivateKey(&example)

	// testcases only include one signature
	assert.Equal(len(example.Input.Sign.Signers), 1)

	signerInput := example.Input.Sign.Signers[0]
	alg := getAlgByNameOrPanic(signerInput.Protected.Alg)
	external := HexToBytesOrDie(signerInput.External)

	decoded, err := Unmarshal(HexToBytesOrDie(example.Output.Cbor))
	assert.Nil(err, fmt.Sprintf("%s: Error decoding example CBOR", example.Title))

	if ExpectCastToFail(example.Title) {
		return
	}

	message, ok := decoded.(SignMessage)
	assert.True(ok, fmt.Sprintf("%s: Error casting example CBOR to SignMessage", example.Title))

	signer, err := NewSignerFromKey(alg, &privateKey)
	assert.Nil(err, fmt.Sprintf("%s: Error creating signer %s", example.Title, err))

	verifier := signer.Verifier()

	// Test Verify - signatures CBOR decoded from example
	assert.NotNil(message.Signatures[0].SignatureBytes)
	err = message.Verify(external, []Verifier{*verifier})
	if example.Fail {
		assert.NotNil(err, fmt.Sprintf("%s: verifying signature did not fail. Got nil instead of error from signature verification failure", example.Title))

		// signing should not necessarily fail and the
		// intermediates are wrong for fail test cases
		return
	}
	assert.Nil(err, fmt.Sprintf("%s: error verifying signature %+v", example.Title, err))

	// Test Sign

	// clear the signature
	message.Signatures[0].SignatureBytes = nil

	err = message.Sign(rand.Reader, external, []Signer{*signer})
	assert.Nil(err, fmt.Sprintf("%s: signing failed with err %s", example.Title, err))

	// check intermediate
	ToBeSigned, err := message.SigStructure(external, &message.Signatures[0])
	assert.Nil(err, fmt.Sprintf("%s: signing failed with err %s", example.Title, err))
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex,
		strings.ToUpper(hex.EncodeToString(ToBeSigned)),
		fmt.Sprintf("%s: signing wrong Hex Intermediate", example.Title))

	// Verify our signature (round trip)
	digest, err := hashSigStructure(ToBeSigned, alg.HashFunc)
	assert.Nil(err, fmt.Sprintf("%s: round trip failed to hash signature %s", example.Title, err))

	err = verifier.Verify(digest, message.Signatures[0].SignatureBytes)
	assert.Nil(err, fmt.Sprintf("%s: round trip signature verification failed with err %s", example.Title, err))
}

var SkipExampleTitles = map[string]bool{
	"ECDSA-01: ECDSA - P-256": false, // ecdsa-01.json
	"ECDSA-02: ECDSA - P-384": false, // ecdsa-02.json

	"ECDSA-03: ECDSA - P-512": false, // ecdsa-03.json

	// not recommended "SHA-256 be used only with curve P-256,
	// SHA-384 be used only with curve P-384, and SHA-512 be used
	// with curve P-521"
	"ECDSA-01: ECDSA - P-256 w/ SHA-512": true, // ecdsa-04.json

	// unsupported message types
	"ECDSA-01: ECDSA - P-256 - sign0":                   true, // ecdsa-sig-01.json
	"ECDSA-sig-02: ECDSA - P-384 - sign1":               true, // ecdsa-sig-02.json
	"ECDSA-03: ECDSA - P-512 - sign0":                   true, // ecdsa-sig-03.json
	"ECDSA-sig-01: ECDSA - P-256 w/ SHA-512 - implicit": true, // ecdsa-sig-04.json
}

func ExpectCastToFail(title string) (shouldFail bool) {
	// (g-k) these decode but not to SignMessages since I
	// haven't found a way to get ugorji/go/codec to use our
	// extension to decode without the right CBOR tag
	return title == "sign-pass-03: Remove CBOR Tag" || title == "sign-fail-01: Wrong CBOR Tag"
}

func TestWGExamples(t *testing.T) {
	examples := append(
		LoadExamples("./test/cose-wg-examples/sign-tests"),
		LoadExamples("./test/cose-wg-examples/ecdsa-examples")...,
	)

	for _, example := range examples {
		t.Run(fmt.Sprintf("Example: %s %v", example.Title, example.Fail), func(t *testing.T) {
			if v, ok := SkipExampleTitles[example.Title]; ok && v {
				return
			}
			WGExampleSignsAndVerifies(t, example)
		})
	}
}
