package mar

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"testing"
)

func TestFirefoxKeys(t *testing.T) {
	testMar := New()
	testMar.AddContent([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "/foo/bar", 0600)

	// add the test rsa key to the list of firefox keys
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&rsa2048Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	FirefoxReleasePublicKeys["unit_test"] = publicKeyPem

	testMar.PrepareSignature(rsa2048Key, rsa2048Key.Public())
	testMar.FinalizeSignatures()

	validKeys, isSigned, err := testMar.VerifyWithFirefoxKeys()
	if err != nil {
		log.Fatal(err)
	}
	if !isSigned {
		t.Fatal("expected signed MAR file but didn't get one")
	}
	if len(validKeys) != 1 || validKeys[0] != "unit_test" {
		t.Fatal("expected signature from 'unit_test' key but didn't get one")
	}
}

func TestBadKey(t *testing.T) {
	var priv dsa.PrivateKey
	params := &priv.Parameters
	err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160)
	if err != nil {
		t.Fatal(err)
	}
	err = dsa.GenerateKey(&priv, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySignature([]byte("0000"), []byte("0000"), SigAlgEcdsaP384Sha384, priv.PublicKey)
	if err == nil {
		t.Fatal("expected to fail with invalid dsa key type but succeeded")
	}
	if err.Error() != "unknown public key type dsa.PublicKey" {
		t.Fatalf("expect to fail with invalid dsa key type but failed with: %v", err)
	}
}
