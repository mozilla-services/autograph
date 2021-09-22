package xpi

import (
	"testing"
	"time"

	"github.com/mozilla-services/autograph/signer"
)

func BenchmarkResignOmnija(b *testing.B) {
	// initialize a system addon signer with an RSA key
	testcase := validSignerConfigs[1]

	// don't use an RSA key cache
	testcase.RSACacheConfig = signer.RSACacheConfig{
		NumKeys:                0,
		NumGenerators:          0,
		GeneratorSleepDuration: 10 * time.Minute,
		FetchTimeout:           0,
		StatsSampleRate:        10 * time.Minute,
	}

	s, err := New(testcase, nil)
	if err != nil {
		b.Fatalf("signer initialization failed with: %v", err)
	}
	signOptions := Options{
		ID:             "omnija+benchmark@mozilla.com",
		COSEAlgorithms: []string{"ES256"},
		PKCS7Digest:    "SHA256",
	}

	for n := 0; n < b.N; n++ {
		// sign both omni.ja files once
		_, err = s.SignFile(fxOmnija, signOptions)
		if err != nil {
			b.Fatalf("failed to sign omni.ja: %v", err)
		}
		_, err = s.SignFile(fxBrowserOmnija, signOptions)
		if err != nil {
			b.Fatalf("failed to sign browser/omni.ja: %v", err)
		}
	}
}
