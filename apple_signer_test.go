// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"testing"

	"github.com/mozilla-services/autograph/crypto11"
	"github.com/mozilla-services/autograph/signer"
	"github.com/mozilla-services/autograph/signer/apple"
)

// a static self-signed Developer ID certificate; New() only needs it to parse.
const appleTestCertPEM = `-----BEGIN CERTIFICATE-----
MIIEBjCCAu6gAwIBAgIBATANBgkqhkiG9w0BAQsFADCBnjEVMBMGCgmSJomT8ixk
AQEMBXVuc2V0MUQwQgYDVQQDDDtEZXZlbG9wZXIgSUQgQXBwbGljYXRpb246IEF1
dG9ncmFwaCBBcHBsZSBVbml0IFRlc3QgKHVuc2V0KTEOMAwGA1UECwwFdW5zZXQx
IjAgBgNVBAoMGUF1dG9ncmFwaCBBcHBsZSBVbml0IFRlc3QxCzAJBgNVBAYTAlhY
MB4XDTI2MDcxNjIyMzU0N1oXDTI3MDcxNjIyMzU0N1owgZ4xFTATBgoJkiaJk/Is
ZAEBDAV1bnNldDFEMEIGA1UEAww7RGV2ZWxvcGVyIElEIEFwcGxpY2F0aW9uOiBB
dXRvZ3JhcGggQXBwbGUgVW5pdCBUZXN0ICh1bnNldCkxDjAMBgNVBAsMBXVuc2V0
MSIwIAYDVQQKDBlBdXRvZ3JhcGggQXBwbGUgVW5pdCBUZXN0MQswCQYDVQQGEwJY
WDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALk91wxAgJcUlhS/l62+
D9vx4Ds+7vjYuTQ79mEBdRt0eRpB7hn6Yh09Zi3cehm29jmKJscYvt4kzfP1Dxvj
D/DbqtmnpNK0Sl1OHazumRLi+URmvQI5pT540CKBlsJit2GprqwUNbhQcLNr7iRd
199f2SAgzWbSO0fEmLFMnRsxNx+0oGXO2JZ/CVgqIcEU2o8Ho4LuIpXXiCSb+jrF
dCHHAci3mYKLII88LF6PMbA6TpO0/4efmG0FSEoXbuklD1BT2pJ9V6kS54NqP+OL
XByBoAGyM6bTqRTREcuvtw0YWSTNrXVB9hbIM8toi1+ffjP3agNYh+xWsIgtLF+b
3IMCAwEAAaNNMEswDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
AzAOBgNVHQ8BAf8EBAMCB4AwEwYKKoZIhvdjZAYBDQEB/wQCBQAwDQYJKoZIhvcN
AQELBQADggEBACI0Qk4cCIft3K15cFWeu0TfG/iICLfkU2udqm+d+g0v8uKbDYdh
+xJlyg34mYPmgoatkTybGQzaC6I+ZAUn06UrRNbZVqIp1hiLQlgAACfua4svigge
Slfu6xtc4k1NX3ZnphEpJoitci1FfxLL2LV/mz+ksasveID0KnsChK4LZ0CJErQV
0OpGV8ccrAq79yRXvuniHWyoBkt03odW/4wgghW6gPLBGbN7CofS4E/2lH4djFUG
Jz0qd20O+jOk5ECITIjHAZOvevugrF1UDyMSJCPtbEfv9IXnjITPicPmVWijrlsO
uoUqwMD40WI+uPbRvVAY7ipxQFgm2/dCNYw=
-----END CERTIFICATE-----
`

// TestAddAppleSigner exercises the apple case in addSigners: a well-formed
// application-mode apple config should load, receiving its PKCS#11 provider
// settings from the autographer's HSM config. New() validates without opening
// the HSM, so a placeholder library path is sufficient here.
func TestAddAppleSigner(t *testing.T) {
	ag := newAutographer(1)
	ag.hsmConfig = crypto11.PKCS11Config{
		Path:       "/nonexistent/libsofthsm2.so",
		TokenLabel: "test",
		Pin:        "0000",
	}
	err := ag.addSigners([]signer.Configuration{{
		ID:          "test-apple",
		Type:        apple.Type,
		Mode:        apple.ModeApplication,
		PrivateKey:  "apple-key-label",
		Certificate: appleTestCertPEM,
	}})
	if err != nil {
		t.Fatalf("addSigners returned an error: %v", err)
	}
	signers := ag.getSigners()
	if len(signers) != 1 {
		t.Fatalf("expected 1 loaded signer, got %d", len(signers))
	}
	if got := signers[0].Config().ID; got != "test-apple" {
		t.Fatalf("loaded signer ID = %q, want test-apple", got)
	}
	if _, ok := signers[0].(signer.FileSigner); !ok {
		t.Error("apple signer should implement signer.FileSigner")
	}
}
