package xpi

import "testing"

func TestMakeEndEntity(t *testing.T) {
	t.Parallel()
	s, err := New(PASSINGTESTCASES[3])
	if err != nil {
		t.Fatal(err)
	}
	for _, testid := range []string{
		"foo@example.net",
		"foo",
		"0000",
		"a0d7ccb3-214d-498b-b4aa-0e8fda9a7bf7",
	} {
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
		if cert.DNSNames[0] != testid {
			t.Fatalf("expected SAN to match testid %q but got %q", testid, cert.Subject.CommonName)
		}
	}
}
