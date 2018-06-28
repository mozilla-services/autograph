package xpi

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMakeEndEntity(t *testing.T) {
	t.Parallel()
	s, err := New(PASSINGTESTCASES[3])
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
		cert, _, err := s.MakeEndEntity(testid)
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
