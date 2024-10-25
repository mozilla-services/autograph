package main

import (
	"crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/mozilla-services/autograph/crypto11"
)

func BenchmarkHSMRandGen(b *testing.B) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		b.Skip("skipping benchmark outside of GKE")
	}

	modulePath := os.Getenv("KMS_PKCS11_MODULE")
	if modulePath == "" {
		b.Skip("skipping benchmark without KMS_PKCS11_MODULE")
	}

	crypto11Config := &crypto11.PKCS11Config{Path: modulePath, TokenLabel: "gcp-autograph-token"}
	_, err := crypto11.Configure(crypto11Config, crypto11.NewDefaultPKCS11Context)
	if err != nil {
		b.Fatal(err)
	}
	reader := &crypto11.PKCS11RandReader{}
	benchRand(b, reader)
}

func BenchmarkLocalRandGen(b *testing.B) {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		b.Skip("skipping benchmark outside of GKE")
	}
	benchRand(b, rand.Reader)
}

// TODO(AUT-335): remove this and the benches that depend on it.
func benchRand(b *testing.B, reader io.Reader) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		n, err := reader.Read(data)
		if n != 1024 {
			b.Errorf("expected to read 1024 bytes, got %d", n)
		}
		if err != nil {
			b.Errorf("unexpected error: %v", err)
		}
	}
}
