package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gomock "github.com/golang/mock/gomock"
	"github.com/mozilla-services/autograph/tools/autograph-monitor/mock_main"
	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer/contentsignaturepki"
)

// helper funcs  -----------------------------------------------------------------

func mustPEMToCert(s string) *x509.Certificate {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		log.Fatalf("Failed to parse certificate PEM")
	}
	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Could not parse X.509 certificate: %v", err)
	}
	return certX509
}

type signOptions struct {
	commonName   string
	extKeyUsages []x509.ExtKeyUsage
	privateKey   *ecdsa.PrivateKey
	isCA         bool
	issuer       *x509.Certificate
	notBefore    time.Time
	notAfter     time.Time
}

func signTestCert(options signOptions) *x509.Certificate {
	var (
		issuer = options.issuer
	)
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Mozilla"},
			// OrganizationalUnit: []string{"Cloud Services Autograph Unit Testing"},
			Country:    []string{"US"},
			Province:   []string{"CA"},
			Locality:   []string{"Mountain View"},
			CommonName: options.commonName,
		},
		DNSNames:              []string{options.commonName},
		NotBefore:             options.notBefore,
		NotAfter:              options.notAfter,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		IsCA:                  options.isCA,
		BasicConstraintsValid: true,
		ExtKeyUsage:           options.extKeyUsages,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if options.issuer == nil {
		issuer = certTpl
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTpl, issuer, options.privateKey.Public(), options.privateKey)
	if err != nil {
		log.Fatalf("Could not self sign an X.509 root certificate: %v", err)
	}
	certX509, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("Could not parse X.509 certificate: %v", err)
	}
	return certX509
}

func sha2Fingerprint(cert *x509.Certificate) string {
	return strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(cert.Raw)))
}

func generateTestKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate private key: %v", err)
	}
	return priv
}

func mustChainToCerts(chain string) (certs []*x509.Certificate) {
	// the first cert is the end entity, then the intermediate and the root
	block, rest := pem.Decode([]byte(chain))
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("failed to PEM decode ee certificate from chain")
	}
	ee, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse ee certificate from chain: %q", err)
	}
	certs = append(certs, ee)

	// the second cert is the intermediate
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("failed to PEM decode intermediate certificate from chain")
	}
	inter, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse intermediate certificate from chain: %q", err)
	}
	certs = append(certs, inter)

	// the third and last cert is the root
	block, rest = pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("failed to PEM decode root certificate from chain")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse root certificate from chain: %q", err)
	}
	if len(rest) != 0 {
		log.Fatalf("trailing data after root certificate in chain")
	}
	certs = append(certs, root)
	return
}

func serverAndWaitForSetup(handlerURI, chain, port string) {
	go func() {
		http.HandleFunc(handlerURI, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, chain)
		})
		log.Fatal(http.ListenAndServe(":"+port, nil))
	}()
	setupTimeout, _ := time.ParseDuration("10s")
	conn, _ := net.DialTimeout("tcp", net.JoinHostPort("", port), setupTimeout)
	if conn != nil {
		conn.Close()
	}
	return
}

// Tests -----------------------------------------------------------------

func TestVerifyContentSignature(t *testing.T) {
	serverAndWaitForSetup("/normandychain", NormandyDevChain2021, "64320")

	err := verifyContentSignature(nil, conf.rootHash, ValidMonitoringContentSignature)
	if err != nil {
		t.Fatalf("Failed to verify monitoring content signature: %v", err)
	}
}

func Test_verifyCertChain(t *testing.T) {
	var typedNilNotifier *PDEventNotifier = nil

	type args struct {
		notifier Notifier
		rootHash string
		certs    []*x509.Certificate
	}
	tests := []struct {
		name                 string
		args                 args
		wantErr              bool
		errSubStr            string
	}{
		{
			name: "expired end-entity chain fails",
			args: args{
				notifier: nil,
				rootHash: conf.rootHash,
				certs:    mustChainToCerts(ExpiredEndEntityChain),
			},
			wantErr:         true,
			errSubStr:       "expired",
		},
		{
			name: "invalid root chain fails",
			args: args{
				notifier: nil,
				rootHash: conf.rootHash,
				certs:    []*x509.Certificate{selfSignedRootNonCA},
			},
			wantErr:         true,
			errSubStr:       "is root but fails validation",
		},
		{
			name: "not yet valid chain fails",
			args: args{
				notifier: nil,
				rootHash: conf.rootHash,
				certs:    []*x509.Certificate{selfSignedRootNotYetValid},
			},
			wantErr:         true,
			errSubStr:       "is not yet valid",
		},
		{
			name: "wrongly ordered chain fails",
			args: args{
				notifier: nil,
				rootHash: conf.rootHash,
				certs:    mustChainToCerts(WronglyOrderedChain),
			},
			wantErr:         true,
			errSubStr:       "is not signed by parent certificate",
		},
		{
			name: "valid chain with typed nil notifier passes",
			args: args{
				notifier: typedNilNotifier,
				rootHash: conf.rootHash,
				certs:    mustChainToCerts(NormandyDevChain2021),
			},
			wantErr:         false,
			errSubStr:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				err      error
				notifier Notifier = tt.args.notifier
			)

			err = verifyCertChain(notifier, tt.args.rootHash, tt.args.certs)

			if tt.wantErr == false && err != nil { // unexpected error
				t.Errorf("verifyCertChain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr == true && err == nil { // unexpected pass
				t.Errorf("verifyCertChain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr == true && !strings.Contains(err.Error(), tt.errSubStr) {
				t.Fatalf("verifyCertChain() expected to fail with %s but failed with: %v", tt.errSubStr, err.Error())
			}
		})
	}
}

func TestVerifyExpiredCertChainNotifySendsWarning(t *testing.T) {
	serverAndWaitForSetup("/expiredcertchain2", ExpiredEndEntityChain, "64322")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mock_main.NewMockNotifier(ctrl)

	// Should notifier.Send once
	m.EXPECT().Send("normandy.content-signature.mozilla.org", "warning", `Certificate 0 for "normandy.content-signature.mozilla.org" expires in less than 30 days: notAfter=2017-11-07 14:02:37 +0000 UTC`)

	chain, err := contentsignaturepki.GetX5U("http://localhost:64322/expiredcertchain2")
	if err != nil && strings.Contains(err.Error(), "failed to retrieve") {
		t.Fatalf("Failed to retrieve certificate chain: %v", err)
	}

	err = verifyCertChain(m, conf.rootHash, chain)
	if err == nil {
		t.Fatal("Expected to fail chain verification with expired end-entity, but succeeded")
	}
	log.Printf("Chain verification failed with: %v", err)
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Expected to failed with expired end-entity but failed with: %v", err)
	}
}

func TestVerifyExpiredCertChainWhenNotifySendWarningErrs(t *testing.T) {
	serverAndWaitForSetup("/expiredcertchain3", ExpiredEndEntityChain, "64323")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mock_main.NewMockNotifier(ctrl)

	// Should notifier.Send once
	m.EXPECT().Send("normandy.content-signature.mozilla.org", "warning", `Certificate 0 for "normandy.content-signature.mozilla.org" expires in less than 30 days: notAfter=2017-11-07 14:02:37 +0000 UTC`).Return(fmt.Errorf("Notifier.send mock error"))

	chain, err := contentsignaturepki.GetX5U("http://localhost:64323/expiredcertchain3")
	if err != nil && strings.Contains(err.Error(), "failed to retrieve") {
		t.Fatalf("Failed to retrieve certificate chain: %v", err)
	}

	err = verifyCertChain(m, conf.rootHash, chain)
	if err == nil {
		t.Fatal("Expected to fail chain verification with expired end-entity, but succeeded")
	}
	log.Printf("Chain verification failed with: %v", err)
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Expected to failed with expired end-entity but failed with: %v", err)
	}
}

func TestVerifyChainNotifyResolvesWarning(t *testing.T) {
	serverAndWaitForSetup("/normandychain2", NormandyDevChain2021, "64327")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mock_main.NewMockNotifier(ctrl)

	// Should notifier.Send three times
	gomock.InOrder(
		m.EXPECT().Send("normandy.content-signature.mozilla.org", "info", `Certificate 0 "normandy.content-signature.mozilla.org" is valid from 2016-07-06 21:57:15 +0000 UTC to 2021-07-05 21:57:15 +0000 UTC`),
		m.EXPECT().Send("Devzilla Signing Services Intermediate 1", "info", `Certificate 1 "Devzilla Signing Services Intermediate 1" is valid from 2016-07-06 21:49:26 +0000 UTC to 2021-07-05 21:49:26 +0000 UTC`),
		m.EXPECT().Send("dev.content-signature.root.ca", "info", `Certificate 2 "dev.content-signature.root.ca" is valid from 2016-07-06 18:15:22 +0000 UTC to 2026-07-04 18:15:22 +0000 UTC`),
	)

	chain, err := contentsignaturepki.GetX5U("http://localhost:64327/normandychain2")
	if err != nil && strings.Contains(err.Error(), "failed to retrieve") {
		t.Fatalf("Failed to retrieve certificate chain: %v", err)
	}

	err = verifyCertChain(m, conf.rootHash, chain)
	if err != nil {
		t.Fatalf("Failed to verify monitoring content signature: %v", err)
	}
}

func TestVerifyChainNotifyResolveWarningErrs(t *testing.T) {
	serverAndWaitForSetup("/normandychain3", NormandyDevChain2021, "64328")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mock_main.NewMockNotifier(ctrl)

	// Should notifier.Send two times
	gomock.InOrder(
		m.EXPECT().Send("normandy.content-signature.mozilla.org", "info", `Certificate 0 "normandy.content-signature.mozilla.org" is valid from 2016-07-06 21:57:15 +0000 UTC to 2021-07-05 21:57:15 +0000 UTC`),
		m.EXPECT().Send("Devzilla Signing Services Intermediate 1", "info", `Certificate 1 "Devzilla Signing Services Intermediate 1" is valid from 2016-07-06 21:49:26 +0000 UTC to 2021-07-05 21:49:26 +0000 UTC`).Return(fmt.Errorf("Notifier.send mock error")),
		m.EXPECT().Send("dev.content-signature.root.ca", "info", `Certificate 2 "dev.content-signature.root.ca" is valid from 2016-07-06 18:15:22 +0000 UTC to 2026-07-04 18:15:22 +0000 UTC`),
	)

	chain, err := contentsignaturepki.GetX5U("http://localhost:64328/normandychain3")
	if err != nil && strings.Contains(err.Error(), "failed to retrieve") {
		t.Fatalf("Failed to retrieve certificate chain: %v", err)
	}

	err = verifyCertChain(m, conf.rootHash, chain)
	if err != nil {
		t.Fatalf("Failed to verify monitoring content signature: %v", err)
	}
}

func Test_verifyRoot(t *testing.T) {
	type args struct {
		rootHash string
		cert     *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "verify Firefox prod root",
			args: args{
				rootHash: firefoxPkiProdRootHash,
				cert:     mustPEMToCert(firefoxPkiProdRoot),
			},
			wantErr: false,
		},
		{
			name: "verify Firefox stage root",
			args: args{
				rootHash: firefoxPkiContentSignatureStageRootHash,
				cert:     mustPEMToCert(firefoxPkiContentSignatureStageRoot),
			},
			wantErr: false,
		},
		{
			name: "verify sign-signed root",
			args: args{
				rootHash: sha2Fingerprint(selfSignedRoot),
				cert:     selfSignedRoot,
			},
			wantErr: false,
		},
		// error testcases
		{
			name: "root not self-signed errs",
			args: args{
				rootHash: sha2Fingerprint(mustPEMToCert(NormandyDevChain2021Intermediate)),
				cert:     mustPEMToCert(NormandyDevChain2021Intermediate),
			},
			wantErr: true,
		},
		{
			name: "root not CA errs",
			args: args{
				rootHash: sha2Fingerprint(selfSignedRootNonCA),
				cert:     selfSignedRootNonCA,
			},
			wantErr: true,
		},
		{
			name: "invalid root hash errs",
			args: args{
				rootHash: "foo",
				cert:     mustPEMToCert(firefoxPkiProdRoot),
			},
			wantErr: true,
		},
		{
			name: "root without code signing ext errs",
			args: args{
				rootHash: sha2Fingerprint(selfSignedRootNoExt),
				cert:     selfSignedRootNoExt,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyRoot(tt.args.rootHash, tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("verifyRoot() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// fixtures -----------------------------------------------------------------

var (
	testKey        = generateTestKey()
	selfSignedRoot = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now(),
		notAfter:     time.Now().Add(time.Hour),
	})
	selfSignedRootNonCA = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testKey,
		isCA:         false,
		issuer:       nil, // self-sign
		notBefore:    time.Now(),
		notAfter:     time.Now().Add(time.Hour),
	})
	selfSignedRootNoExt = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		extKeyUsages: []x509.ExtKeyUsage{},
		privateKey:   testKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now(),
		notAfter:     time.Now().Add(time.Hour),
	})
	selfSignedRootNotYetValid = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(3 * time.Hour),
		notAfter:     time.Now().Add(60 * 24 * time.Hour),
	})

	ValidMonitoringContentSignature = formats.SignatureResponse{
		Ref:       "1881ks1du39bi26cfmfczu6pf3",
		Type:      "contentsignature",
		Mode:      "p384ecdsa",
		SignerID:  "normankey",
		PublicKey: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVEKiCAIkwRg1VFsP8JOYdSF6a3qvgbRPoEK9eTuLbrB6QixozscKR4iWJ8ZOOX6RPCRgFdfVDoZqjFBFNJN9QtRBk0mVtHbnErx64d2vMF0oWencS1hyLW2whgOgOz7p",
		Signature: "9M26T-1RCEzTAlCzDZk6CkEZxkVZkt-wUJfA4s4altKx3Vw-MfuE08bXy1TenbR0I87PzuuA9c1CNOZ8hzRbVuYvKnOH0z4kIbGzAMWzyOxwRgufaODHpcnSAKv2q3JM",
		X5U:       "http://127.0.0.1:64320/normandychain",
	}
)

// This chain has an expired end-entity certificate
var ExpiredEndEntityChain = `-----BEGIN CERTIFICATE-----
MIIEnTCCBCSgAwIBAgIEAQAAFzAKBggqhkjOPQQDAzCBpjELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMSUwIwYDVQQDExxDb250ZW50
IFNpZ25pbmcgSW50ZXJtZWRpYXRlMSEwHwYJKoZIhvcNAQkBFhJmb3hzZWNAbW96
aWxsYS5jb20wHhcNMTcwNTA5MTQwMjM3WhcNMTcxMTA3MTQwMjM3WjCBrzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExHDAaBgNVBAoTE01vemlsbGEg
Q29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZu
b3JtYW5keS5jb250ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzEjMCEGCSqGSIb3
DQEJARYUc2VjdXJpdHlAbW96aWxsYS5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAShRFsGyg6DkUX+J2mMDM6cLK8V6HawjGVlQ/w5H5fHiGJDMrkl4ktnN+O37mSs
dReHcVxxpPNEpIfkWQ2TFmJgOUzqi/CzO06APlAJ9mnIcaobgdqRQxoTchFEyzUx
nTijggIWMIICEjAdBgNVHQ4EFgQUKnGLJ9po8ea5qUNjJyV/c26VZfswgaoGA1Ud
IwSBojCBn4AUiHVymVvwUPJguD2xCZYej3l5nu6hgYGkfzB9MQswCQYDVQQGEwJV
UzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxs
YSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3Qt
Y2EtcHJvZHVjdGlvbi1hbW+CAxAABjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE
AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzBFBgNVHR8EPjA8MDqgOKA2hjRo
dHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNkbi5tb3ppbGxhLm5ldC9jYS9jcmwu
cGVtMEMGCWCGSAGG+EIBBAQ2FjRodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNk
bi5tb3ppbGxhLm5ldC9jYS9jcmwucGVtME8GCCsGAQUFBwEBBEMwQTA/BggrBgEF
BQcwAoYzaHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5jZG4ubW96aWxsYS5uZXQv
Y2EvY2EucGVtMDEGA1UdEQQqMCiCJm5vcm1hbmR5LmNvbnRlbnQtc2lnbmF0dXJl
Lm1vemlsbGEub3JnMAoGCCqGSM49BAMDA2cAMGQCMGeeyXYM3+r1fcaXzd90PwGb
h9nrl1fZNXrCu17lCPn2JntBVh7byT3twEbr+Hmv8gIwU9klAW6yHLG/ZpAZ0jdf
38Rciz/FDEAdrzH2QlYAOw+uDdpcmon9oiRgIxzwNlUe
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFfjCCA2agAwIBAgIDEAAGMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNVBAYTAlVT
MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3ppbGxh
IEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMWcm9vdC1j
YS1wcm9kdWN0aW9uLWFtbzAeFw0xNzA1MDQwMDEyMzlaFw0xOTA1MDQwMDEyMzla
MIGmMQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEv
MC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2Ux
JTAjBgNVBAMTHENvbnRlbnQgU2lnbmluZyBJbnRlcm1lZGlhdGUxITAfBgkqhkiG
9w0BCQEWEmZveHNlY0Btb3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BMCmt4C33KfMzsyKokc9SXmMSxozksQglhoGAA1KjlgqEOzcmKEkxtvnGWOA9FLo
A6U7Wmy+7sqmvmjLboAPQc4G0CEudn5Nfk36uEqeyiyKwKSAT+pZsqS4/maXIC7s
DqOCAYkwggGFMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB
/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSIdXKZW/BQ8mC4PbEJlh6PeXme7jCB
qAYDVR0jBIGgMIGdgBSzvOpYdKvhbngqsqucIx6oYyyXt6GBgaR/MH0xCzAJBgNV
BAYTAlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZN
b3ppbGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMW
cm9vdC1jYS1wcm9kdWN0aW9uLWFtb4IBATAzBglghkgBhvhCAQQEJhYkaHR0cDov
L2FkZG9ucy5hbGxpem9tLm9yZy9jYS9jcmwucGVtME4GA1UdHgRHMEWgQzAggh4u
Y29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwH4IdY29udGVudC1zaWduYXR1
cmUubW96aWxsYS5vcmcwDQYJKoZIhvcNAQEMBQADggIBAKWhLjJB8XmW3VfLvyLF
OOUNeNs7Aju+EZl1PMVXf+917LB//FcJKUQLcEo86I6nC3umUNl+kaq4d3yPDpMV
4DKLHgGmegRsvAyNFQfd64TTxzyfoyfNWH8uy5vvxPmLvWb+jXCoMNF5FgFWEVon
5GDEK8hoHN/DMVe0jveeJhUSuiUpJhMzEf6Vbo0oNgfaRAZKO+VOY617nkTOPnVF
LSEcUPIdE8pcd+QP1t/Ysx+mAfkxAbt+5K298s2bIRLTyNUj1eBtTcCbBbFyWsly
rSMkJihFAWU2MVKqvJ74YI3uNhFzqJ/AAUAPoet14q+ViYU+8a1lqEWj7y8foF3r
m0ZiQpuHULiYCO4y4NR7g5ijj6KsbruLv3e9NyUAIRBHOZEKOA7EiFmWJgqH1aZv
/eS7aQ9HMtPKrlbEwUjV0P3K2U2ljs0rNvO8KO9NKQmocXaRpLm+s8PYBGxby92j
5eelLq55028BSzhJJc6G+cRT9Hlxf1cg2qtqcVJa8i8wc2upCaGycZIlBSX4gj/4
k9faY4qGuGnuEdzAyvIXWMSkb8jiNHQfZrebSr00vShkUEKOLmfFHbkwIaWNK0+2
2c3RL4tDnM5u0kvdgWf0B742JskkxqqmEeZVofsOZJLOhXxO9NO/S0hM16/vf/tl
Tnsnhv0nxUR0B9wxN7XmWmq4
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`

// This chain is in the wrong order: the intermediate cert is
// placed first, followed by the EE then the root
var WronglyOrderedChain = `
-----BEGIN CERTIFICATE-----
MIIFfzCCA2egAwIBAgIDEAAJMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNVBAYTAlVT
MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3ppbGxh
IEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMWcm9vdC1j
YS1wcm9kdWN0aW9uLWFtbzAiGA8yMDIwMTIzMTAwMDAwMFoYDzIwMjUwMzE0MjI1
MzU3WjCBozELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRp
b24xLzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2
aWNlMUUwQwYDVQQDDDxDb250ZW50IFNpZ25pbmcgSW50ZXJtZWRpYXRlL2VtYWls
QWRkcmVzcz1mb3hzZWNAbW96aWxsYS5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAQklaclq89BKPcYIfUdVS4JF/pZxjTVOlYVdj4QJ5xopHAngXkUggYkkHj0tmZV
EcrXrCVq1qEtB/k7wXXkU4HN9rX7WcUkksClDJmUQ2qabzP7i20q3epGNq57RE2p
3hKjggGJMIIBhTAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUB
Af8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUoB1KF0+Mwis1RfFj8dpwcKfO+OEw
gagGA1UdIwSBoDCBnYAUs7zqWHSr4W54KrKrnCMeqGMsl7ehgYGkfzB9MQswCQYD
VQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMm
TW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMT
FnJvb3QtY2EtcHJvZHVjdGlvbi1hbW+CAQEwMwYJYIZIAYb4QgEEBCYWJGh0dHA6
Ly9hZGRvbnMuYWxsaXpvbS5vcmcvY2EvY3JsLnBlbTBOBgNVHR4ERzBFoEMwIIIe
LmNvbnRlbnQtc2lnbmF0dXJlLm1vemlsbGEub3JnMB+CHWNvbnRlbnQtc2lnbmF0
dXJlLm1vemlsbGEub3JnMA0GCSqGSIb3DQEBDAUAA4ICAQALeUuF/7hcmM/LFnK6
6a5lBQk5z5JBr2bNNvKVs/mtdIcVKcxjWxOBM5rorZiM5UWE7BmAm8E7gFCCq30y
ZnNn6BO04z5LtDRHxa3IGhgECloyOJUSi9xxFxe5p5wJzFdArl7happSOUwOi+z2
aDqS6uTJWubIY4Uz7h7S2UkUm52CTYnvpioS7eQoovvrlUsgIhkkIwDQnu7RWSej
6nkc5o5SNwAJWsQvxIko32AxhvPmmtv1T/mtXY488TJ0VoBZ6lRkJJIxIJ48pGHJ
+YRt1tzO2aqCEs9pNPGWfhrpcDc2mu4fvlSX1elWYiGrpQBVbdEJlDkGAD0AC8on
/7ybD2pEdh7pViVLV78Md+DNNquqqNhRJpn65k4lhvgDLHYvLNOrrtAmcmQonNdU
OSumIuqcGk7dm/7gr9lrwAm8V8/GwDyzTgi4wNA4vwln3c7iMFGLL/b2piEQCSl+
mqL1LeWJV+8rkbi8l2T0QIBwjDgR97ZxpLPwmUdDNiGAWeEFxn0jU9CQtQKjOj84
VPZUM7aSHhVQ0bQpnjua7IWvLKK7F2fOo3PmuLacnnfyrzr2C/Le5k6EK/0q2cKf
P6JzDWwt8werc6E3C6z3jbUdAwgNpv/fGz8gQBPf7NeiYkqMUNB2Z3aF8He8Jg15
Abv+2+rSOLpBsTU67AHzMKJ8hw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEnTCCBCSgAwIBAgIEAQAAFzAKBggqhkjOPQQDAzCBpjELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMSUwIwYDVQQDExxDb250ZW50
IFNpZ25pbmcgSW50ZXJtZWRpYXRlMSEwHwYJKoZIhvcNAQkBFhJmb3hzZWNAbW96
aWxsYS5jb20wHhcNMTcwNTA5MTQwMjM3WhcNMTcxMTA3MTQwMjM3WjCBrzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExHDAaBgNVBAoTE01vemlsbGEg
Q29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZu
b3JtYW5keS5jb250ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzEjMCEGCSqGSIb3
DQEJARYUc2VjdXJpdHlAbW96aWxsYS5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAShRFsGyg6DkUX+J2mMDM6cLK8V6HawjGVlQ/w5H5fHiGJDMrkl4ktnN+O37mSs
dReHcVxxpPNEpIfkWQ2TFmJgOUzqi/CzO06APlAJ9mnIcaobgdqRQxoTchFEyzUx
nTijggIWMIICEjAdBgNVHQ4EFgQUKnGLJ9po8ea5qUNjJyV/c26VZfswgaoGA1Ud
IwSBojCBn4AUiHVymVvwUPJguD2xCZYej3l5nu6hgYGkfzB9MQswCQYDVQQGEwJV
UzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxs
YSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3Qt
Y2EtcHJvZHVjdGlvbi1hbW+CAxAABjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE
AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzBFBgNVHR8EPjA8MDqgOKA2hjRo
dHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNkbi5tb3ppbGxhLm5ldC9jYS9jcmwu
cGVtMEMGCWCGSAGG+EIBBAQ2FjRodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNk
bi5tb3ppbGxhLm5ldC9jYS9jcmwucGVtME8GCCsGAQUFBwEBBEMwQTA/BggrBgEF
BQcwAoYzaHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5jZG4ubW96aWxsYS5uZXQv
Y2EvY2EucGVtMDEGA1UdEQQqMCiCJm5vcm1hbmR5LmNvbnRlbnQtc2lnbmF0dXJl
Lm1vemlsbGEub3JnMAoGCCqGSM49BAMDA2cAMGQCMGeeyXYM3+r1fcaXzd90PwGb
h9nrl1fZNXrCu17lCPn2JntBVh7byT3twEbr+Hmv8gIwU9klAW6yHLG/ZpAZ0jdf
38Rciz/FDEAdrzH2QlYAOw+uDdpcmon9oiRgIxzwNlUe
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`

var NormandyDevChain2021Intermediate = `-----BEGIN CERTIFICATE-----
MIIHijCCBXKgAwIBAgIEAQAABDANBgkqhkiG9w0BAQwFADCBvzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSYwJAYDVQQK
Ex1Db250ZW50IFNpZ25hdHVyZSBEZXYgU2lnbmluZzEmMCQGA1UEAxMdZGV2LmNv
bnRlbnQtc2lnbmF0dXJlLnJvb3QuY2ExOzA5BgkqhkiG9w0BCQEWLGNsb3Vkc2Vj
K2RldnJvb3Rjb250ZW50c2lnbmF0dXJlQG1vemlsbGEuY29tMB4XDTE2MDcwNjIx
NDkyNloXDTIxMDcwNTIxNDkyNlowazELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0Fs
bGl6b20xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMTEwLwYDVQQDEyhEZXZ6aWxs
YSBTaWduaW5nIFNlcnZpY2VzIEludGVybWVkaWF0ZSAxMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAypIfUURYgWzGw8G/1Pz9zW+Tsjirx2owThiv2gys
wJiWL/9/2gzKOrYDEqlDUudfA/BjVRtT9+NbYgnhaCkNfADOAacWS83aMhedAqhP
bVd5YhGQdpijI7f1AVTSb0ehrU2nhOZHvHX5Tk2fbRx3ryefIazNTLFGpiMBbsNv
tSI/+fjW8s0MhKNqlLnk6a9mZKo0mEy7HjGYV8nzsgI17rKLx/s2HG4TFG0+JQzc
UGlum3Tg58ritDzWdyKIkmKNZ48oLBX99Qc8j8B1UyiLv6TZmjVX0I+Ds7eSWHZk
0axLEpTyf2r7fHvN4iDNCPajw+ZpuuBfbs80Ha8b8MHvnpf9fbwiirodNQOVpY4c
t5E3Us3eYwBKdqDEbECWxCKGAS2/iVVUCNKHsg0sSxgqcwxrxyrddQRUQ0EM38DZ
F/vHt+vTdHt07kezbjJe0Kklel59uSpghA0iL4vxzbTns1fuwYOgVrNGs3acTkiB
GhFOxRXUPGtpdYmv+AaR9WlWJQY1GIEoVrinPVH7bcCwyh1CcUbHL+oAFTcmc6kZ
7azNg21tWILIRL7R0IZYQm0tF5TTwCsjVC7FuHaBtkxtVrrZqeKjvVXQ8TK5VoI0
BUQ6BKHGeTtm+0HBpheYBDy3wkOsEGbGHLEM6cMeiz6PyCXF8wXli8Qb/TjN3LHZ
e30CAwEAAaOCAd8wggHbMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGG
MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBT9huhQhcCi8KESm50M
G6h0cpuNSzCB7AYDVR0jBIHkMIHhgBSDx8s0qJaMyQCehKcuzgzVNRA75qGBxaSB
wjCBvzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFp
biBWaWV3MSYwJAYDVQQKEx1Db250ZW50IFNpZ25hdHVyZSBEZXYgU2lnbmluZzEm
MCQGA1UEAxMdZGV2LmNvbnRlbnQtc2lnbmF0dXJlLnJvb3QuY2ExOzA5BgkqhkiG
9w0BCQEWLGNsb3Vkc2VjK2RldnJvb3Rjb250ZW50c2lnbmF0dXJlQG1vemlsbGEu
Y29tggEBMEIGCWCGSAGG+EIBBAQ1FjNodHRwczovL2NvbnRlbnQtc2lnbmF0dXJl
LmRldi5tb3phd3MubmV0L2NhL2NybC5wZW0wTgYIKwYBBQUHAQEEQjBAMD4GCCsG
AQUFBzAChjJodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmRldi5tb3phd3MubmV0
L2NhL2NhLnBlbTANBgkqhkiG9w0BAQwFAAOCAgEAbum0z0ccqI1Wp49VtsGmUPHA
gjPPy2Xa5NePmqY87WrGdhjN3xbLVb3hx8T2N6pqDjMY2rEynXKEOek3oJkQ3C6J
8AFP6Y93gaAlNz6EA0J0mqdW5TMI8YEYsu2ma+dQQ8wm9f/5b+/Y8qwfhztP06W5
H6IG04/RvgUwYMnSR4QvT309fu5UmCRUDzsO53ZmQCfmN94u3NxHc4S6n0Q6AKAM
kh5Ld9SQnlqqqDykzn7hYDi8nTLWc7IYqkGfNMilDEKbAl4CjnSfyEvpdFAJ9sPR
UL+kaWFSMvaqIPNpxS5OpoPZjmxEc9HHnCHxtfDHWdXTJILjijPrCdMaxOCHfIqV
5roOJggI4RZ0YM68IL1MfN4IEVOrHhKjDHtd1gcmy2KU4jfj9LQq9YTnyvZ2z1yS
lS310HG3or1K8Nnu5Utfe7T6ppX8bLRMkS1/w0p7DKxHaf4D/GJcCtM9lcSt9JpW
6ACKFikjWR4ZxczYKgApc0wcjd7XBuO5777xtOeyEUDHdDft3jiXA91dYM5UAzc3
69z/3zmaELzo0gWcrjLXh7fU9AvbU4EUF6rwzxbPGF78jJcGK+oBf8uWUCkBykDt
VsAEZI1u4EDg8e/C1nFqaH9gNMArAgquYIB9rve+hdprIMnva0S147pflWopBWcb
jwzgpfquuYnnxe0CNBA=
-----END CERTIFICATE-----`

var NormandyDevChain2021 = `-----BEGIN CERTIFICATE-----
MIIGRTCCBC2gAwIBAgIEAQAABTANBgkqhkiG9w0BAQwFADBrMQswCQYDVQQGEwJV
UzEQMA4GA1UEChMHQWxsaXpvbTEXMBUGA1UECxMOQ2xvdWQgU2VydmljZXMxMTAv
BgNVBAMTKERldnppbGxhIFNpZ25pbmcgU2VydmljZXMgSW50ZXJtZWRpYXRlIDEw
HhcNMTYwNzA2MjE1NzE1WhcNMjEwNzA1MjE1NzE1WjCBrzELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCkNhbGlmb3JuaWExHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRp
b24xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZub3JtYW5keS5j
b250ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzEjMCEGCSqGSIb3DQEJARYUc2Vj
dXJpdHlAbW96aWxsYS5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARUQqIIAiTB
GDVUWw/wk5h1IXpreq+BtE+gQr15O4tusHpCLGjOxwpHiJYnxk45fpE8JGAV19UO
hmqMUEU0k31C1EGTSZW0ducSvHrh3a8wXShZ6dxLWHItbbCGA6A7PumjggJYMIIC
VDAdBgNVHQ4EFgQUVfksSjlZ0i1TBiS1vcoObaMeXn0wge8GA1UdIwSB5zCB5IAU
/YboUIXAovChEpudDBuodHKbjUuhgcWkgcIwgb8xCzAJBgNVBAYTAlVTMQswCQYD
VQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEmMCQGA1UEChMdQ29udGVu
dCBTaWduYXR1cmUgRGV2IFNpZ25pbmcxJjAkBgNVBAMTHWRldi5jb250ZW50LXNp
Z25hdHVyZS5yb290LmNhMTswOQYJKoZIhvcNAQkBFixjbG91ZHNlYytkZXZyb290
Y29udGVudHNpZ25hdHVyZUBtb3ppbGxhLmNvbYIEAQAABDAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzBEBgNVHR8E
PTA7MDmgN6A1hjNodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmRldi5tb3phd3Mu
bmV0L2NhL2NybC5wZW0wQgYJYIZIAYb4QgEEBDUWM2h0dHBzOi8vY29udGVudC1z
aWduYXR1cmUuZGV2Lm1vemF3cy5uZXQvY2EvY3JsLnBlbTBOBggrBgEFBQcBAQRC
MEAwPgYIKwYBBQUHMAKGMmh0dHBzOi8vY29udGVudC1zaWduYXR1cmUuZGV2Lm1v
emF3cy5uZXQvY2EvY2EucGVtMDEGA1UdEQQqMCiCJm5vcm1hbmR5LmNvbnRlbnQt
c2lnbmF0dXJlLm1vemlsbGEub3JnMA0GCSqGSIb3DQEBDAUAA4ICAQCwb+8JTAB7
ZfQmFqPUIV2cQQv696AaDPQCtA9YS4zmUfcLMvfZVAbK397zFr0RMDdLiTUQDoeq
rBEmPXhJRPiv6JAK4n7Jf6Y6XfXcNxx+q3garR09Vm/0CnEq/iV+ZAtPkoKIO9kr
Nkzecd894yQCF4hIuPQ5qtMySeqJmH3Dp13eq4T0Oew1Bu32rNHuBJh2xYBkWdun
aAw/YX0I5EqZBP/XA6gbiA160tTK+hnpnlMtw/ljkvfhHbWpICD4aSiTL8L3vABQ
j7bqjMKR5xDkuGWshZfcmonpvQhGTye/RZ1vz5IzA3VOJt1mz5bdZlitpaOm/Yv0
x6aODz8GP/PiRWFQ5CW8Uf/7pGc5rSyvnfZV2ix8EzFlo8cUtuN1fjrPFPOFOLvG
iiB6S9nlXiKBGYIDdd8V8iC5xJpzjiAWJQigwSNzuc2K30+iPo3w0zazkwe5V8jW
gj6gItYxh5xwVQTPHD0EOd9HvV1ou42+rH5Y+ISFUm25zz02UtUHEK0BKtL0lmdt
DwVq5jcHn6bx2/iwUtlKvPXtfM/6JjTJlkLZLtS7U5/pwcS0owo9zAL0qg3bdm16
+v/olmPqQFLUHmamJTzv3rojj5X/uVdx1HMM3wBjV9tRYoYaZw9RIInRmM8Z1pHv
JJ+CIZgCyd5vgp57BKiodRZcgHoCH+BkOQ==
-----END CERTIFICATE-----
` + NormandyDevChain2021Intermediate + `
-----BEGIN CERTIFICATE-----
MIIH3DCCBcSgAwIBAgIBATANBgkqhkiG9w0BAQwFADCBvzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSYwJAYDVQQKEx1D
b250ZW50IFNpZ25hdHVyZSBEZXYgU2lnbmluZzEmMCQGA1UEAxMdZGV2LmNvbnRl
bnQtc2lnbmF0dXJlLnJvb3QuY2ExOzA5BgkqhkiG9w0BCQEWLGNsb3Vkc2VjK2Rl
dnJvb3Rjb250ZW50c2lnbmF0dXJlQG1vemlsbGEuY29tMB4XDTE2MDcwNjE4MTUy
MloXDTI2MDcwNDE4MTUyMlowgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEW
MBQGA1UEBxMNTW91bnRhaW4gVmlldzEmMCQGA1UEChMdQ29udGVudCBTaWduYXR1
cmUgRGV2IFNpZ25pbmcxJjAkBgNVBAMTHWRldi5jb250ZW50LXNpZ25hdHVyZS5y
b290LmNhMTswOQYJKoZIhvcNAQkBFixjbG91ZHNlYytkZXZyb290Y29udGVudHNp
Z25hdHVyZUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAJcPcXhD8MzF6OTn5qZ0L7lX1+PEgLKhI9g1HxxDYDVup4Zm0kZhPGmFSlml
6eVO99OvvHdAlHhQGCIG7h+w1cp66mWjfpcvtQH23uRoKZfiW3jy1jUWrvdXolxR
t1taZosjzo+9OP8TvG6LpJj7AvqUiYD4wYnQJtt0jNRN4d6MUfQwiavSS5uTBuxd
ZJ4TsPvEI+Iv4A4PSobSzxkg79LTMvsGtDLQv7nN5hMs9T18EL5GnIKoqnSQCU0d
n2CN7S3QiQ+cbORWsSYqCTj1gUbFh6X3duEB/ypLcyWFbqeJmPHikjY8q8pLjZSB
IYiTJYLyvYlKdM5QleC/xuBNnMPCftrwwLHjWE4Dd7C9t7k0R5xyOetuiHLCwOcQ
tuckp7RgFKoviMNv3gdkzwVapOklcsaRkRscv6OMTKJNsdJVIDLrPF1wMABhbEQB
64BL0uL4lkFtpXXbJzQ6mgUNQveJkfUWOoB+cA/6GtI4J0aQfvQgloCYI6jxNn/e
Nvk5OV9KFOhXS2dnDft3wHU46sg5yXOuds1u6UrOoATBNFlkS95m4zIX1Svu091+
CKTiLK85+ZiFtAlU2bPr3Bk3GhL3Z586ae6a4QUEx6SPQVXc18ezB4qxKqFc+avI
ylccYMRhVP+ruADxtUM5Vy6x3U8BwBK5RLdecRx2FEBDImY1AgMBAAGjggHfMIIB
2zAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAK
BggrBgEFBQcDAzAdBgNVHQ4EFgQUg8fLNKiWjMkAnoSnLs4M1TUQO+YwgewGA1Ud
IwSB5DCB4YAUg8fLNKiWjMkAnoSnLs4M1TUQO+ahgcWkgcIwgb8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEmMCQGA1UE
ChMdQ29udGVudCBTaWduYXR1cmUgRGV2IFNpZ25pbmcxJjAkBgNVBAMTHWRldi5j
b250ZW50LXNpZ25hdHVyZS5yb290LmNhMTswOQYJKoZIhvcNAQkBFixjbG91ZHNl
YytkZXZyb290Y29udGVudHNpZ25hdHVyZUBtb3ppbGxhLmNvbYIBATBCBglghkgB
hvhCAQQENRYzaHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5l
dC9jYS9jcmwucGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6
Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJ
KoZIhvcNAQEMBQADggIBAAAQ+fotZE79FfZ8Lz7eiTUzlwHXCdSE2XD3nMROu6n6
uLTBPrf2C+k+U1FjKVvL5/WCUj6hIzP2X6Sb8+o0XHX9mKN0yoMORTEYJOnazYPK
KSUUFnE4vGgQkr6k/31gGRMTICdnf3VOOAlUCQ5bOmGIuWi401E3sbd85U+TJe0A
nHlU+XjtfzlqcBvQivdbA0s+GEG55uRPvn952aTBEMHfn+2JqKeLShl4AtUAfu+h
6md3Z2HrEC7B3GK8ekWPu0G/ZuWTuFvOimZ+5C8IPRJXcIR/siPQl1x6dpTCew6t
lPVcVuvg6SQwzvxetkNrGUe2Wb2s9+PK2PUvfOS8ee25SNmfG3XK9qJpqGUhzSBX
T8QQgyxd0Su5G7Wze7aaHZd/fqIm/G8YFR0HiC2xni/lnDTXFDPCe+HCnSk0bH6U
wpr6I1yK8oZ2IdnNVfuABGMmGOhvSQ8r7//ea9WKhCsGNQawpVWVioY7hpyNAJ0O
Vn4xqG5f6allz8lgpwAQ+AeEEClHca6hh6mj9KhD1Of1CC2Vx52GHNh/jMYEc3/g
zLKniencBqn3Y2XH2daITGJddcleN09+a1NaTkT3hgr7LumxM8EVssPkC+z9j4Vf
Gbste+8S5QCMhh00g5vR9QF8EaFqdxCdSxrsA4GmpCa5UQl8jtCnpp2DLKXuOh72
-----END CERTIFICATE-----`
