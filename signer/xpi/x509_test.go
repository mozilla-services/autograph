package xpi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestMakeEndEntity(t *testing.T) {
	t.Parallel()
	s, err := New(PASSINGTESTCASES[3], nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, testid := range []string{
		"foo",
		"0000",
		"a0d7ccb3-214d-498b-b4aa-0e8fda9a7bf7",
		"NavratnePeniaze@NávratnéPeniaze.com",
		"foo-bar@baz",
	} {
		cndigest := sha256.Sum256([]byte(testid))
		dnsname := fmt.Sprintf("%x.%x.addons.mozilla.org", cndigest[:16], cndigest[16:])
		cert, _, err := s.MakeEndEntity(testid, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != testid {
			t.Fatalf("expected cert cn to match testid %q but got %q", testid, cert.Subject.CommonName)
		}
		if len(cert.DNSNames) != 1 {
			t.Fatalf("expected to find 1 SAN entry but found %d", len(cert.DNSNames))
		}
		if cert.DNSNames[0] != dnsname {
			t.Fatalf("expected SAN to match testid %q but got %q", testid, cert.DNSNames[0])
		}
	}
}

func TestRsaCaching(t *testing.T) {
	t.Parallel()

	// initialize a rsa signer
	testcase := PASSINGTESTCASES[0]
	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	keySize := s.issuerKey.(*rsa.PrivateKey).N.BitLen()

	go s.populateRsaCache(keySize)
	if os.Getenv("CI") == "true" {
		// sleep longer when running in continuous integration
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(10 * time.Second)
	}
	// retrieving a rsa key should be really fast now
	start := time.Now()
	key, err := s.getRsaKey(keySize)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	cachedElapsed := time.Since(start)
	t.Logf("retrieved rsa key from cache in %s", cachedElapsed)

	start = time.Now()
	rsa.GenerateKey(rand.Reader, keySize)
	generatedElapsed := time.Since(start)
	t.Logf("generated rsa key without cache in %s", generatedElapsed)

	if cachedElapsed > generatedElapsed {
		t.Fatal("key retrieval from populated cache took longer than generating directly")
	}
	if key.N.BitLen() != keySize {
		t.Fatalf("key bitlen does not match. expected %d, got %d", keySize, key.N.BitLen())
	}
}

func TestGetRsaKeyRace(t *testing.T) {
	t.Parallel()

	// initialize a rsa signer
	testcase := PASSINGTESTCASES[0]
	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	keySize := s.issuerKey.(*rsa.PrivateKey).N.BitLen()

	go s.populateRsaCache(keySize)
	if os.Getenv("CI") == "true" {
		// sleep longer when running in continuous integration
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(10 * time.Second)
	}

	// get the rsa key 5 times, which is the max reusability value
	// so we should get the same key 5 times
	var wg sync.WaitGroup
	var key1, key2, key3, key4, key5 *rsa.PrivateKey
	wg.Add(5)
	go func() {
		key1, _ = s.getRsaKey(keySize)
		wg.Done()
	}()
	go func() {
		key2, _ = s.getRsaKey(keySize)
		wg.Done()
	}()
	go func() {
		key3, _ = s.getRsaKey(keySize)
		wg.Done()
	}()
	go func() {
		key4, _ = s.getRsaKey(keySize)
		wg.Done()
	}()
	go func() {
		key5, _ = s.getRsaKey(keySize)
		wg.Done()
	}()

	wg.Wait()
	if key1 == nil || key1 != key2 || key2 != key3 || key3 != key5 || key4 != key5 {
		t.Fatalf("expected key1 to have same pointer, but differ: %p, %p, %p, %p, %p",
			key1, key2, key3, key4, key5)
	}

	// now the next call to getRsaKey should return a different key on a new pointer
	key6, _ := s.getRsaKey(keySize)
	if bytes.Equal(key1.N.Bytes(), key6.N.Bytes()) ||
		key1 == key6 {
		t.Fatalf("expected key1 and key6 to have different values and pointers, but they match")
	}
}

func TestRsaCacheExpiration(t *testing.T) {
	t.Parallel()

	// initialize a rsa signer
	testcase := PASSINGTESTCASES[0]
	// change key max age to 1s
	testcase.RSACacheConfig.KeyMaxAge = 1000000000
	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	keySize := s.issuerKey.(*rsa.PrivateKey).N.BitLen()

	go s.populateRsaCache(keySize)
	if os.Getenv("CI") == "true" {
		// sleep longer when running in continuous integration
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(10 * time.Second)
	}
	key1, _ := s.getRsaKey(keySize)
	// sleep longer than the configuration key max age
	time.Sleep(2 * time.Second)
	key2, _ := s.getRsaKey(keySize)

	if bytes.Equal(key1.N.Bytes(), key2.N.Bytes()) ||
		key1 == key2 {
		t.Fatalf("expected key1 and key2 to have different values and pointers, but they match")
	}
}

func TestRsaNoReuse(t *testing.T) {
	t.Parallel()

	// initialize a rsa signer
	testcase := PASSINGTESTCASES[0]
	// change key max age to 1s
	testcase.RSACacheConfig.KeyMaxUsage = 0
	s, err := New(testcase, nil)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	keySize := s.issuerKey.(*rsa.PrivateKey).N.BitLen()

	go s.populateRsaCache(keySize)
	if os.Getenv("CI") == "true" {
		// sleep longer when running in continuous integration
		time.Sleep(30 * time.Second)
	} else {
		time.Sleep(10 * time.Second)
	}
	key1, _ := s.getRsaKey(keySize)
	key2, _ := s.getRsaKey(keySize)

	if bytes.Equal(key1.N.Bytes(), key2.N.Bytes()) ||
		key1 == key2 {
		t.Fatalf("expected key1 and key2 to have different values and pointers, but they match")
	}
}
