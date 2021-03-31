package xpi

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/mozilla-services/autograph/signer"
)

func BenchmarkResignOmnija(b *testing.B) {
	var (
		err                             error = nil
		omnijaBytes, browserOmnijaBytes []byte
	)

	omnijaBytes, err = ioutil.ReadFile("test/fixtures/firefox-70.0.1/omni.ja")
	if err != nil {
		b.Fatalf("failed to read omni.ja test file with: %s", err)
	}
	browserOmnijaBytes, err = ioutil.ReadFile("test/fixtures/firefox-70.0.1/browser/omni.ja")
	if err != nil {
		b.Fatalf("failed to read omni.ja test file with: %s", err)
	}

	// initialize a system addon signer with an RSA key
	testcase := PASSINGTESTCASES[1]

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
		_, err = s.SignFile(omnijaBytes, signOptions)
		if err != nil {
			b.Fatalf("failed to sign omni.ja: %v", err)
		}
		_, err = s.SignFile(browserOmnijaBytes, signOptions)
		if err != nil {
			b.Fatalf("failed to sign browser/omni.ja: %v", err)
		}
	}
}
