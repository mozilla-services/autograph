package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"testing"
)

func TestSign(t *testing.T) {
	content := []byte("Hello World")
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			var parents []*x509.Certificate
			parents = append(parents, interCert.Certificate)
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}
				for _, testDetach := range []bool{false, true} {
					log.Printf("test %s/%s/%s detached %t\n", sigalgroot, sigalginter, sigalgsigner, testDetach)
					toBeSigned, err := NewSignedData(content)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot initialize signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}

					// Set the digest to match the end entity cert
					signerDigest, _ := getDigestOIDForSignatureAlgorithm(signerCert.Certificate.SignatureAlgorithm)
					toBeSigned.SetDigestAlgorithm(signerDigest)

					if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
						t.Fatalf("test %s/%s/%s: cannot add signer: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						toBeSigned.Detach()
					}
					signed, err := toBeSigned.Finish()
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot finish signing data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
					p7, err := Parse(signed)
					if err != nil {
						t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if testDetach {
						p7.Content = content
					}
					if !bytes.Equal(content, p7.Content) {
						t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
					}
					if err := p7.VerifyWithChain(truststore); err != nil {
						t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
					}
					if !signerDigest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
						t.Errorf("test %s/%s/%s: expected digest algorithm %q but got %q",
							sigalgroot, sigalginter, sigalgsigner, signerDigest, p7.Signers[0].DigestAlgorithm.Algorithm)
					}
				}
			}
		}
	}
}

func TestSignAndVerifyWithOpenSSL(t *testing.T) {
	content := []byte("Hello World")
	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestSignAndVerifyWithOpenSSL_content")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for i, sigalg := range sigalgs {
		log.Printf("test case %d sigalg %s\n", i, sigalg)
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalg, true)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot generate root cert: %s", i, sigalg, err)
		}
		// write the root cert to a temp file
		tmpRootCertFile, err := ioutil.TempFile("", "TestSignAndVerifyWithOpenSSL_root")
		if err != nil {
			t.Fatal(err)
		}
		fd, err := os.OpenFile(tmpRootCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Certificate.Raw})
		fd.Close()

		interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate CA", rootCert, sigalg, true)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot generate intermediate cert: %s", i, sigalg, err)
		}
		var intermediates []*x509.Certificate
		intermediates = append(intermediates, interCert.Certificate)
		signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalg, false)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot generate signer cert: %s", i, sigalg, err)
		}

		// write the signer cert to a temp file
		tmpSignerCertFile, err := ioutil.TempFile("", "TestSignAndVerifyWithOpenSSL_signer")
		if err != nil {
			t.Fatal(err)
		}
		fd, err = os.OpenFile(tmpSignerCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			t.Fatal(err)
		}
		pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Certificate.Raw})
		fd.Close()

		toBeSigned, err := NewSignedData(content)
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot initialize signed data: %s", i, sigalg, err)
		}
		if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, intermediates, SignerInfoConfig{}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		toBeSigned.Detach()
		signed, err := toBeSigned.Finish()
		if err != nil {
			t.Fatalf("test case %d sigalg %s: cannot finish signing data: %s", i, sigalg, err)
		}

		// write the signature to a temp file
		tmpSignatureFile, err := ioutil.TempFile("", "TestSignAndVerifyWithOpenSSL_signature")
		if err != nil {
			t.Fatal(err)
		}
		ioutil.WriteFile(tmpSignatureFile.Name(), pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: signed}), 0755)

		// call openssl to verify the signature on the content using the root
		opensslCMD := exec.Command("openssl", "smime", "-verify",
			"-in", tmpSignatureFile.Name(), "-inform", "PEM",
			"-content", tmpContentFile.Name(),
			"-CAfile", tmpRootCertFile.Name())
		out, err := opensslCMD.CombinedOutput()
		if err != nil {
			t.Fatalf("test case %d sigalg %s: openssl command failed with %s: %s", i, sigalg, err, out)
		}
		os.Remove(tmpSignatureFile.Name()) // clean up
		os.Remove(tmpRootCertFile.Name())  // clean up
	}
	os.Remove(tmpContentFile.Name()) // clean up
}

func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

func TestUnmarshalSignedAttribute(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	testValue := "TestValue"
	if err := toBeSigned.AddSigner(cert.Certificate, *cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{Attribute{Type: oidTest, Value: testValue}},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	var actual string
	err = p7.UnmarshalSignedAttribute(oidTest, &actual)
	if err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
}

func TestDegenerateCertificate(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA1WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: deg})
}

// writes the cert to a temporary file and tests that openssl can read it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	tmpCertFile, err := ioutil.TempFile("", "testCertificate")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCertFile.Name()) // clean up

	if _, err := tmpCertFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}

	opensslCMD := exec.Command("openssl", "pkcs7", "-inform", "der", "-in", tmpCertFile.Name())
	_, err = opensslCMD.Output()
	if err != nil {
		t.Fatal(err)
	}

	if err := tmpCertFile.Close(); err != nil {
		t.Fatal(err)
	}

}
