package cose

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"testing"
)

// signing tests for Firefox Addon COSE Signatures
//

func RustCoseVerifiesGoCoseSignatures(t *testing.T, testCase RustTestCase) {
	fmt.Println(fmt.Sprintf("%s", testCase.Title))

	assert := assert.New(t)
	assert.True(len(testCase.Params) > 0, "No signature params!")

	signers := []Signer{}
	verifiers := []Verifier{}

	message := NewSignMessage()
	msgHeaders := &Headers{
		Protected:   map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{},
	}
	msgHeaders.Protected[kidTag] = testCase.Certs
	message.Headers = msgHeaders
	message.Payload = []byte(testCase.SignPayload)

	for _, param := range testCase.Params {
		key, err := x509.ParsePKCS8PrivateKey(param.pkcs8)
		assert.Nil(err)

		signer, err := NewSignerFromKey(param.algorithm, key)
		assert.Nil(err, fmt.Sprintf("%s: Error creating signer %s", testCase.Title, err))
		signers = append(signers, *signer)
		verifiers = append(verifiers, *signer.Verifier())

		sig := NewSignature()
		sig.Headers.Protected[algTag] = param.algorithm.Value
		sig.Headers.Protected[kidTag] = param.certificate

		message.AddSignature(sig)
	}
	assert.True(len(message.Signatures) > 0)
	assert.Equal(len(message.Signatures), len(signers))

	var external []byte

	err := message.Sign(rand.Reader, external, signers)
	assert.Nil(err, fmt.Sprintf("%s: signing failed with err %s", testCase.Title, err))

	if testCase.ModifySignature {
		// tamper with the COSE signature.
		sig1 := message.Signatures[0].SignatureBytes
		sig1[len(sig1)-5] ^= sig1[len(sig1)-5]
	}
	if testCase.ModifyPayload {
		message.Payload[0] ^= message.Payload[0]
	}

	message.Payload = nil

	// Verify our signature with cose-rust

	// encode message and signature
	msgBytes, err := Marshal(message)
	assert.Nil(err, fmt.Sprintf("%s: Error marshaling signed message to bytes %s", testCase.Title, err))

	// Make sure cose-rust can verify our signature too
	cmd := exec.Command("cargo", "run", "--quiet", "--color", "never", "--example", "sign_verify",
		"--",
		"verify",
		hex.EncodeToString([]byte(testCase.SignPayload)),
		hex.EncodeToString(msgBytes))

	cmd.Dir = "./test/cose-rust"
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-A dead_code -A unused_imports")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	if testCase.ModifySignature || testCase.ModifyPayload {
		assert.NotNil(err, fmt.Sprintf("%s: verifying signature with cose-rust did not fail %s", testCase.Title, err))
	} else {
		assert.Nil(err, fmt.Sprintf("%s: error verifying signature with cose-rust %s", testCase.Title, err))
	}
}

func TestRustCoseCli(t *testing.T) {
	for _, testCase := range RustTestCases {
		t.Run(testCase.Title, func(t *testing.T) {
			RustCoseVerifiesGoCoseSignatures(t, testCase)
		})
	}
}
