package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/tools/autograph-monitor/mock_main"
	"go.uber.org/mock/gomock"
)

// helper funcs  -----------------------------------------------------------------

func generateTestKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate private key: %v", err)
	}
	return priv
}

func generateTestRSAKey() *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Could not generate private key: %v", err)
	}
	return priv
}

func mustPEMToECKey(s string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		log.Fatalf("Failed to parse EC key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Could not parse EC key: %q", err)
	}
	return key
}

type signOptions struct {
	commonName                  string
	extKeyUsages                []x509.ExtKeyUsage
	keyUsage                    x509.KeyUsage
	privateKey                  *ecdsa.PrivateKey
	publicKey                   crypto.PublicKey
	isCA                        bool
	issuer                      *x509.Certificate
	notBefore                   time.Time
	notAfter                    time.Time
	permittedDNSDomainsCritical bool
	permittedDNSDomains         []string
	DNSNames                    []string
}

func signTestCert(options signOptions) *x509.Certificate {
	var (
		issuer = options.issuer
	)
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:       []string{"Mozilla"},
			OrganizationalUnit: []string{"Cloud Services Autograph Unit Testing"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"Mountain View"},
			CommonName:         options.commonName,
		},
		DNSNames:                    options.DNSNames,
		NotBefore:                   options.notBefore,
		NotAfter:                    options.notAfter,
		SignatureAlgorithm:          x509.ECDSAWithSHA384,
		IsCA:                        options.isCA,
		BasicConstraintsValid:       true,
		ExtKeyUsage:                 options.extKeyUsages,
		KeyUsage:                    options.keyUsage,
		PermittedDNSDomainsCritical: options.permittedDNSDomainsCritical,
		PermittedDNSDomains:         options.permittedDNSDomains,
	}
	if options.issuer == nil {
		issuer = certTpl
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTpl, issuer, options.publicKey, options.privateKey)
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

func mustCertsToChain(certs []*x509.Certificate) (chain []byte) {
	for _, cert := range certs {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return chain
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

// Tests -----------------------------------------------------------------

func Test_verifyContentSignature(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, NormandyDevChain2021)
	}))
	defer ts.Close()

	oneCertChainTestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, NormandyDevChain2021Intermediate)
	}))
	defer oneCertChainTestServer.Close()

	rsaLeafChainTestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(rsaLeafChain))
	}))
	defer rsaLeafChainTestServer.Close()

	testLeafChainTestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(testLeafChain))
	}))
	defer testLeafChainTestServer.Close()

	testLeafExpiringSoonChainTestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(mustCertsToChain([]*x509.Certificate{testLeaf7DaysToExpiration, testInter, testRoot})))
	}))
	defer testLeafExpiringSoonChainTestServer.Close()

	testInterExpiringSoonChainTestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(mustCertsToChain([]*x509.Certificate{testLeaf, testInter30DaysToExpiration, testRoot})))
	}))
	defer testInterExpiringSoonChainTestServer.Close()

	testRootExpiringSoonChainTestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(mustCertsToChain([]*x509.Certificate{testLeaf, testInter, testRoot16DaysToExpiration})))
	}))
	defer testRootExpiringSoonChainTestServer.Close()

	// TODO: replace type with pointer to a notifier
	// implementation when another is added
	var typedNilNotifier Notifier

	type args struct {
		x5uClient                  *http.Client
		notifier                   Notifier
		rootHashes                 []string
		ignoredExpirationSignerIds []string
		ignoredCerts               map[string]bool
		response                   formats.SignatureResponse
		input                      []byte
	}
	tests := []struct {
		name                 string
		args                 args
		wantErr              bool
		errSubStr            string
		useMockNotifier      bool
		mockNotifierCallback func(m *mock_main.MockNotifier)
	}{
		{
			name: "valid csig response",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{sha2Fingerprint(testRoot)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testLeafChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr: false,
		},
		{
			name: "valid csig response typed nil notifier ok",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   typedNilNotifier,
				rootHashes: []string{sha2Fingerprint(testRoot)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testLeafChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr: false,
		},
		{
			name: "valid csig response notifies",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{sha2Fingerprint(testRoot)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testLeafChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:         false,
			useMockNotifier: true,
			mockNotifierCallback: func(m *mock_main.MockNotifier) {
				gomock.InOrder(
					m.EXPECT().Send("example.content-signature.mozilla.org", "info", fmt.Sprintf(`Certificate 0 "example.content-signature.mozilla.org" is valid from %s to %s`, testLeaf.NotBefore, testLeaf.NotAfter)).Return(fmt.Errorf("Notifier.send mock error")),
					m.EXPECT().Send("autograph unit test content signing intermediate", "info", fmt.Sprintf(`Certificate 1 "autograph unit test content signing intermediate" is valid from %s to %s`, testInter.NotBefore, testInter.NotAfter)),
					m.EXPECT().Send("autograph unit test self-signed root", "info", fmt.Sprintf(`Certificate 2 "autograph unit test self-signed root" is valid from %s to %s`, testRoot.NotBefore, testRoot.NotAfter)),
				)
			},
		},
		{
			name: "valid csig response with invalid root hash but ignored EE ok",
			args: args{
				x5uClient:    testLeafChainTestServer.Client(),
				notifier:     nil,
				rootHashes:   []string{"invalidroothash"},
				ignoredCerts: map[string]bool{"example.content-signature.mozilla.org": true},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testLeafChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr: false,
		},
		// failing test cases.
		{
			name: "valid csig response with invalid root hash fails",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{"invalidroothash"},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testLeafChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:   true,
			errSubStr: "hash does not match an expected root",
		},
		{
			name: "empty x5u fails",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{"invalidroothash"},
				response: formats.SignatureResponse{
					X5U: "",
				},
				input: []byte(inputdata),
			},
			wantErr:   true,
			errSubStr: "missing an X5U to fetch",
		},
		{
			name: "invalid x5u fails",
			args: args{
				x5uClient: &http.Client{
					Timeout: 1 * time.Nanosecond,
				},
				notifier:   nil,
				rootHashes: normandyDev2021Roothash,
				response: formats.SignatureResponse{
					Ref:       "1881ks1du39bi26cfmfczu6pf3",
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					PublicKey: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVEKiCAIkwRg1VFsP8JOYdSF6a3qvgbRPoEK9eTuLbrB6QixozscKR4iWJ8ZOOX6RPCRgFdfVDoZqjFBFNJN9QtRBk0mVtHbnErx64d2vMF0oWencS1hyLW2whgOgOz7p",
					Signature: "9M26T-1RCEzTAlCzDZk6CkEZxkVZkt-wUJfA4s4altKx3Vw-MfuE08bXy1TenbR0I87PzuuA9c1CNOZ8hzRbVuYvKnOH0z4kIbGzAMWzyOxwRgufaODHpcnSAKv2q3JM",
					X5U:       "http://misbehaving.site/",
				},
			},
			wantErr:   true,
			errSubStr: "failed to retrieve x5u",
		},
		{
			name: "truncated signature fails",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{sha2Fingerprint(testRoot)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "too short",
					X5U:       testLeafChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:   true,
			errSubStr: "error unmarshal content signature",
		},
		{
			name: "one cert X5U chain fails",
			args: args{
				x5uClient:  oneCertChainTestServer.Client(),
				notifier:   nil,
				rootHashes: normandyDev2021Roothash,
				response: formats.SignatureResponse{
					Ref:       "1881ks1du39bi26cfmfczu6pf3",
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					PublicKey: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC84BSoJiLfcYgCr2EVV5Vodc7oW_zKhVBGqR2-90YYoFy3UfBSKjOVTQkU2KDg0vzvVFg8qjCoX0jYxqh_g5SYBBhMM-5WDyZtdk2ul1IhxsVxll13W1OTy8DWUOT_NiwAoeaKQaV8QeDRWRPgVvKEnjq9T7qyPhO7JAK1FXbaTQIDAQAB",
					Signature: "9M26T-1RCEzTAlCzDZk6CkEZxkVZkt-wUJfA4s4altKx3Vw-MfuE08bXy1TenbR0I87PzuuA9c1CNOZ8hzRbVuYvKnOH0z4kIbGzAMWzyOxwRgufaODHpcnSAKv2q3JM",
					X5U:       oneCertChainTestServer.URL,
				},
			},
			wantErr:   true,
			errSubStr: "failed to parse x5u",
		},
		{
			name: "bad EE pubkey fails",
			args: args{
				x5uClient:  rsaLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: normandyDev2021Roothash,
				response: formats.SignatureResponse{
					Ref:       "1881ks1du39bi26cfmfczu6pf3",
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					PublicKey: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC84BSoJiLfcYgCr2EVV5Vodc7oW_zKhVBGqR2-90YYoFy3UfBSKjOVTQkU2KDg0vzvVFg8qjCoX0jYxqh_g5SYBBhMM-5WDyZtdk2ul1IhxsVxll13W1OTy8DWUOT_NiwAoeaKQaV8QeDRWRPgVvKEnjq9T7qyPhO7JAK1FXbaTQIDAQAB",
					Signature: "9M26T-1RCEzTAlCzDZk6CkEZxkVZkt-wUJfA4s4altKx3Vw-MfuE08bXy1TenbR0I87PzuuA9c1CNOZ8hzRbVuYvKnOH0z4kIbGzAMWzyOxwRgufaODHpcnSAKv2q3JM",
					X5U:       rsaLeafChainTestServer.URL,
				},
			},
			wantErr:   true,
			errSubStr: "cannot verify EE/leaf cert with non-ECDSA public key type",
		},
		{
			name: "invalid data (wrong EE for normandyDev2021Roothash) fails",
			args: args{
				x5uClient:  testLeafChainTestServer.Client(),
				notifier:   nil,
				rootHashes: normandyDev2021Roothash,
				response: formats.SignatureResponse{
					Ref:       "1881ks1du39bi26cfmfczu6pf3",
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					PublicKey: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVEKiCAIkwRg1VFsP8JOYdSF6a3qvgbRPoEK9eTuLbrB6QixozscKR4iWJ8ZOOX6RPCRgFdfVDoZqjFBFNJN9QtRBk0mVtHbnErx64d2vMF0oWencS1hyLW2whgOgOz7p",
					Signature: "9M26T-1RCEzTAlCzDZk6CkEZxkVZkt-wUJfA4s4altKx3Vw-MfuE08bXy1TenbR0I87PzuuA9c1CNOZ8hzRbVuYvKnOH0z4kIbGzAMWzyOxwRgufaODHpcnSAKv2q3JM",
					X5U:       testLeafChainTestServer.URL,
				},
			},
			wantErr:   true,
			errSubStr: "ecdsa signature verification failed",
		},
		{
			name: "expiring EE fails",
			args: args{
				x5uClient:  testLeafExpiringSoonChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{sha2Fingerprint(testRoot)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testLeafExpiringSoonChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:   true,
			errSubStr: `leaf/EE certificate 0 "example.content-signature.mozilla.org" expires in less than 15 days`,
		},
		{
			name: "expiring inter fails",
			args: args{
				x5uClient:  testInterExpiringSoonChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{sha2Fingerprint(testRoot)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testInterExpiringSoonChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:   true,
			errSubStr: `intermediate certificate 1 "autograph unit test content signing intermediate" expires in less than 15 weeks`,
		},
		{
			name: "expiring root fails",
			args: args{
				x5uClient:  testRootExpiringSoonChainTestServer.Client(),
				notifier:   nil,
				rootHashes: []string{sha2Fingerprint(testRoot16DaysToExpiration)},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testRootExpiringSoonChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:   true,
			errSubStr: `root certificate 2 "autograph unit test self-signed root" expires in less than 15 months`,
		},
		{name: "expiring root's expiration is ignored",
			args: args{
				x5uClient:                  &http.Client{},
				notifier:                   nil,
				rootHashes:                 []string{sha2Fingerprint(testRoot16DaysToExpiration)},
				ignoredExpirationSignerIds: []string{"normankey"},
				response: formats.SignatureResponse{
					Type:      "contentsignature",
					Mode:      "p384ecdsa",
					SignerID:  "normankey",
					Signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
					X5U:       testRootExpiringSoonChainTestServer.URL,
				},
				input: signerTestData,
			},
			wantErr:   false,
			errSubStr: "",
		},
	}
	for _, tt := range tests {
		notifier := tt.args.notifier
		if tt.useMockNotifier {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := mock_main.NewMockNotifier(ctrl)
			tt.mockNotifierCallback(m)
			notifier = m
		}

		t.Run(tt.name, func(t *testing.T) {
			err := verifyContentSignature(tt.args.x5uClient, notifier, tt.args.rootHashes, tt.args.ignoredCerts, tt.args.ignoredExpirationSignerIds, tt.args.response, tt.args.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("verifyContentSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr == true && !strings.Contains(err.Error(), tt.errSubStr) {
				t.Fatalf("verifyContentSignature() expected to fail with %s but failed with: %v", tt.errSubStr, err.Error())
			}
		})
	}
}

func Test_certChainValidityNotifications(t *testing.T) {
	type args struct {
		certs []*x509.Certificate
	}
	tests := []struct {
		name string
		args args
		// NB: wantNotifications .Message matches on a
		// substring to avoid hardcoding specific datetimes
		wantNotifications []*CertNotification
	}{
		{
			name: "expired end-entity chain",
			args: args{
				certs: mustChainToCerts(ExpiredEndEntityChain),
			},
			wantNotifications: []*CertNotification{
				&CertNotification{
					CN:       "normandy.content-signature.mozilla.org",
					Severity: "warning",
					Message:  `Certificate 0 "normandy.content-signature.mozilla.org" expired: notAfter=2017-11-07 14:02:37 +0000 UTC`,
				},
				&CertNotification{
					CN:       "Content Signing Intermediate",
					Severity: "warning",
					Message:  `Certificate 1 "Content Signing Intermediate" expired: notAfter=2019-05-04 00:12:39 +0000 UTC`,
				},
				&CertNotification{
					CN:       "root-ca-production-amo",
					Severity: "info",
					Message:  `Certificate 2 "root-ca-production-amo" is valid from 2024-02-01 00:00:00 +0000 UTC to 2200-12-03 00:00:00 +0000 UTC`,
				},
			},
		},
		{
			name: "not yet valid root",
			args: args{
				certs: []*x509.Certificate{testRootNotYetValid},
			},
			wantNotifications: []*CertNotification{
				&CertNotification{
					CN:       "autograph unit test self-signed root",
					Severity: "warning",
					Message:  `Certificate 0 "autograph unit test self-signed root" is not yet valid: notBefore=`,
				},
			},
		},
		{
			name: "valid root expiring in <15 days",
			args: args{
				certs: []*x509.Certificate{testRoot7DaysToExpiration},
			},
			wantNotifications: []*CertNotification{
				&CertNotification{
					CN:       "autograph unit test self-signed root",
					Severity: "warning",
					Message:  `Certificate 0 "autograph unit test self-signed root" expires in less than 15 days:`,
				},
			},
		},
		{
			name: "valid root expiring in <30 days",
			args: args{
				certs: []*x509.Certificate{testRoot16DaysToExpiration},
			},
			wantNotifications: []*CertNotification{
				&CertNotification{
					CN:       "autograph unit test self-signed root",
					Severity: "warning",
					Message:  `Certificate 0 for "autograph unit test self-signed root" expires in less than 30 days:`,
				},
			},
		},
		{
			name: "wrongly ordered chain",
			args: args{
				certs: mustChainToCerts(WronglyOrderedChain),
			},
			wantNotifications: []*CertNotification{
				&CertNotification{
					CN:       "Content Signing Intermediate",
					Severity: "info",
					Message:  `Certificate 0 "Content Signing Intermediate" is valid from 2015-03-17 00:00:00 +0000 UTC to 2101-05-19 00:00:00 +0000 UTC`,
				},
				&CertNotification{
					CN:       "remote-settings.content-signature.mozilla.org",
					Severity: "warning",
					Message:  `Certificate 1 "remote-settings.content-signature.mozilla.org" expired: notAfter=2025-01-30 22:06:39 +0000 UTC`,
				},
				&CertNotification{
					CN:       "root-ca-production-amo",
					Severity: "info",
					Message:  `Certificate 2 "root-ca-production-amo" is valid from 2024-02-01 00:00:00 +0000 UTC to 2200-12-03 00:00:00 +0000 UTC`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifications := certChainValidityNotifications(tt.args.certs)

			if len(tt.wantNotifications) != len(notifications) {
				t.Errorf("certChainValidityNotifications() len(notifications) = %d, len(wantNotifications) %d", len(notifications), len(tt.wantNotifications))
				return
			}
			for i, notification := range notifications {
				if notification.CN != tt.wantNotifications[i].CN {
					t.Errorf("certChainValidityNotifications() notifications[%d].CN = %+v, wantNotifications[%d].CN %+v", i, notification.CN, i, tt.wantNotifications[i].CN)
				}
				if notification.Severity != tt.wantNotifications[i].Severity {
					t.Errorf("certChainValidityNotifications() notifications[%d].Severity = %+v, wantNotifications[%d].Severity %+v", i, notification.Severity, i, tt.wantNotifications[i].Severity)
				}
				if !strings.Contains(notification.Message, tt.wantNotifications[i].Message) {
					t.Errorf("certChainValidityNotifications() notifications[%d].Message does not contain '%s', got '%s'", i, tt.wantNotifications[i].Message, notification.Message)
				}
			}
		})
	}
}

// fixtures -----------------------------------------------------------------

// P384ECDSA test signer from signer/contentsignature/contentsignature_test.go TestSign
const testSignerP384PEM = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
/5Cp6z37rpp781N4haUOIauM14P4KUw=
-----END EC PRIVATE KEY-----`

var (
	// from signer/contentsignature/contentsignature_test.go TestSign
	signerTestData = []byte("foobarbaz1234abcd")

	testRootKey    = generateTestKey()
	testInterKey   = generateTestKey()
	testLeafKey    = mustPEMToECKey(testSignerP384PEM)
	testLeafRSAKey = generateTestRSAKey()

	testRoot = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(-3 * day),
		notAfter:     time.Now().Add(24 * month),
	})
	testRoot7DaysToExpiration = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(-3 * day),
		notAfter:     time.Now().Add(7 * day),
	})
	testRoot16DaysToExpiration = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(-3 * day),
		notAfter:     time.Now().Add(16 * day),
	})
	testRootNotYetValid = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(2 * time.Hour),
		notAfter:     time.Now().Add(4 * time.Hour),
	})
	testInter = signTestCert(signOptions{
		commonName:                  "autograph unit test content signing intermediate",
		extKeyUsages:                []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		privateKey:                  testRootKey,
		publicKey:                   &testInterKey.PublicKey,
		isCA:                        true,
		issuer:                      testRoot,
		notBefore:                   time.Now().Add(-2 * day),
		notAfter:                    time.Now().Add(6 * month),
		permittedDNSDomainsCritical: true,
		permittedDNSDomains:         []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	})
	testInter30DaysToExpiration = signTestCert(signOptions{
		commonName:                  "autograph unit test content signing intermediate",
		extKeyUsages:                []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		privateKey:                  testRootKey,
		publicKey:                   &testInterKey.PublicKey,
		isCA:                        true,
		issuer:                      testRoot,
		notBefore:                   time.Now().Add(-2 * day),
		notAfter:                    time.Now().Add(30 * day),
		permittedDNSDomainsCritical: true,
		permittedDNSDomains:         []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	})

	testLeaf = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(60 * day),
	})
	testLeaf7DaysToExpiration = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(7 * day),
	})
	testLeafRSAPub = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafRSAKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(time.Hour),
	})

	rsaLeafChain  = mustCertsToChain([]*x509.Certificate{testLeafRSAPub, testInter, testRoot})
	testLeafChain = mustCertsToChain([]*x509.Certificate{testLeaf, testInter, testRoot})
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
MIIGZTCCBE2gAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wIhgPMjAyNDAyMDEwMDAwMDBaGA8yMjAwMTIwMzAwMDAw
MFowfTELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24x
LzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNl
MR8wHQYDVQQDExZyb290LWNhLXByb2R1Y3Rpb24tYW1vMIICIDANBgkqhkiG9w0B
AQEFAAOCAg0AMIICCAKCAgEAtLth11268Mt+vjD3in+Y4KAEjHzDc+5iVgXnCYL5
U3+IRyWy8zD7CFGrsyPRhKS3x3WesM0shTm+ADPg9ZsQFobmSdzAwCTn9wdUbOkK
Kx65fKqpTbTxqnqZ6TSXC6OybEqqhNzVJu9jIKiB0YE0bKlLPuyyDxnu9utlPjf0
9Cz2FS3uK2dkQx6GmYWGO2vfuPZhziP4NmBQfvcmYxPl3aZU9pAYAOD/HW+4uyNL
SIuG9AdDesvTIS/gkWScsXRXtsAcpCV9eC7IXirDNWsx42Tuekija1vFQCUy5KUc
QprIk69PH5z8gypmnmdAbbLoInHYqXGaV64iBprGWyNdqucrsI0hC3ZA1elGo6Np
/tsLObl6z9+Nl+9VoloQv3ReXc9SyrYwXZlJMWkDDj/7obVxCga2aNaLpw0UMdY+
/kpEOARMIwd0hLa+1w1hjnDiJKCWVjwAnwSwtzyQgVo0wMgZbndAuZ9wsva3oAAJ
ziKiNbdehlNpWkYe3pSe4D0TYEIMC13mXBccOsL8ohHJgozhEOjzPFEI7YTrCpbM
zIZSsL48jhg6M7ZKkgcv7/gLMezltkO65VXymqy9JkRGXUjH6Mt804LTFQjNL4TZ
es3L3+RzTaKaBHYOcrl6NnIWdadSfqvOm9BuciUTHk9vojlWNhEN+7R66lFEZ3As
uLsCAQOjge0wgeowDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0l
AQH/BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFLO86lh0q+FueCqyq5wjHqhjLJe3
MIGSBgNVHSMEgYowgYehgYGkfzB9MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96
aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlv
biBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1h
bW+CAQEwDQYJKoZIhvcNAQEMBQADggIBAAAJuN23qDiyAZ8y9DhqTfIfdYBXC7jg
f7p5DNCj6mcfLxCMLuSvLljYWm0IfHYs5W0lnQgm8+N0m3SAjQd18AzWfXNklFjZ
1EcP8MRU/keFEk9SmeHZhP916jQfqQvB45w4QwPcJG0nPkWsYzceqD3uL5g2g4Jg
gk+WYWmtE4eeM2BX6cT0itMErYKWei3SF09TdrCX+XpHMixg4nnDdsGe9wxc8F/o
diQ48f/7AZo06moMyZvIH4PPcVt0osAU18fLO0RrVJkupMraxbM1XXL1UwJlyV+p
kvJutX2xBB1f1BA3xPl3NlQneaLIm3JFsw0r7t0z0n1shC6xCi4+t3Fh6Z38CnbS
WwAe5rA2OCQYMjsehxRK9BhmDCG8U65GVd9t8nV4iEJFTrjntBDEFtVD5s4Qnlyv
OUrWd2du4dLCs+WW2E6+R7jZtrsIqFD6qwCLqcgBgC9CM9UgHeUBOixmZLBKCNDE
N1sRkmcVwXcCl5btdgVVq74Mgsd38xsmYuFoMi6nbDLllm6T2ql8LZExyX2i/vo0
pxhEVRaFwj1J1r3TRNXksjdqFcgpNCMf2FRbjDGtVLXRVG0DCCGRayigKgdH78qM
HpdXrbaTDFsfMLTAMnGFnqOZMuMobNJS5M6/vqdepoC8L7xmI5dQgW8YGyymr8DP
gchMof0tylgn
-----END CERTIFICATE-----`

// This chain is in the wrong order: the intermediate cert is
// placed first, followed by the EE then the root
var WronglyOrderedChain = `-----BEGIN CERTIFICATE-----
MIIFbzCCA1egAwIBAgIFFykQh0AwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMC
VVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemls
bGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290
LWNhLXByb2R1Y3Rpb24tYW1vMCIYDzIwMTUwMzE3MDAwMDAwWhgPMjEwMTA1MTkw
MDAwMDBaMIGRMQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3Jh
dGlvbjE9MDsGA1UECxM0TW96aWxsYSBDb250ZW50IFNpZ25hdHVyZSBQcm9kdWN0
aW9uIFNpZ25pbmcgU2VydmljZTElMCMGA1UEAxMcQ29udGVudCBTaWduaW5nIElu
dGVybWVkaWF0ZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABKJnirGDz2mekuFBwHAM
dy6zzgM3QLXpGYk7knNGUwJzgRRLttULbtX6P/nJ7BR17YUiaYdQU1Wbnn+GM5SO
x1fqahX3OtZbYBIJfv8igbHKyf4GzpBWzmku+sfPE6XwUqOCAYkwggGFMAwGA1Ud
EwQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMD
MB0GA1UdDgQWBBRYxR116Nzt8ryAtGbr6rke+PVUBDCBqAYDVR0jBIGgMIGdgBSz
vOpYdKvhbngqsqucIx6oYyyXt6GBgaR/MH0xCzAJBgNVBAYTAlVTMRwwGgYDVQQK
ExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3ppbGxhIEFNTyBQcm9k
dWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMWcm9vdC1jYS1wcm9kdWN0
aW9uLWFtb4IBATAzBglghkgBhvhCAQQEJhYkaHR0cDovL2FkZG9ucy5hbGxpem9t
Lm9yZy9jYS9jcmwucGVtME4GA1UdHgRHMEWgQzAggh4uY29udGVudC1zaWduYXR1
cmUubW96aWxsYS5vcmcwH4IdY29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcw
DQYJKoZIhvcNAQEMBQADggIBAGB5toTP4Dbwzgzy2HQn+fk/a5J7JNfkAWkonjlD
Yq46ROm2u265a/iyXRhSXi6GAL+UX8bUD/BowYNhHKg9EfapzhrGlRcaFD28ERah
Ab2EuDi/uiQx/l2bkYOesuiujA0UypCxMFKyvKdy8uose8OFHCDEJyPzVv8gJMEw
OVyUTuj2RdfQ7C0TcbU9k4YdGT/gckNWdHcD+x4mFt9+1bTrRTa9147n5j4i4lSa
HO3V4nR1ijKry4TQ4jJaSdw62sMIf5/CJt1+d/iq7wwau6WOdKnXYlO6C8udyayO
ugPDV01SZ8cAg6GwgHDTp/UnrtAtwWOWbUSchVrCJEr/4lW3QipiqVBAbTmKIRME
9U3p1AMnqoq+Z2oXgstK8qkh5sZm8Jr9rhxp43HibGUqaKe4EdsLn0gqtWs/YMSw
gtOOTyXOwBCysVtm1WMOU9NOqLfFfzHRPGjw37UGFZ2S02oj03PUEEW1YhftdfWR
HS3zISUrM5Whc6+K++DSgxlrPurFWrBN1tqZWuAAS7Vm6WUxuj8hcdzXt5myl/Dp
Ikby1WaFL+7Yv0Y020OmGBy/o0UKhcmF8rUix0cfRlHJ1qrodM320HENC13xUBe/
mqmBtW0Ur3mMvkjUcEbQkt18cMJdXvA7esIyqyS3UvU8EydExYg3YCBE9yg2H1/o
Vugq
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIC9DCCAnmgAwIBAgIIGBA+tArZs6kwCgYIKoZIzj0EAwMwgZExCzAJBgNVBAYT
AlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMT0wOwYDVQQLEzRNb3pp
bGxhIENvbnRlbnQgU2lnbmF0dXJlIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNl
MSUwIwYDVQQDExxDb250ZW50IFNpZ25pbmcgSW50ZXJtZWRpYXRlMB4XDTI0MTEx
MTIyMDYzOVoXDTI1MDEzMDIyMDYzOVowgakxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
EwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNN
b3ppbGxhIENvcnBvcmF0aW9uMRcwFQYDVQQLEw5DbG91ZCBTZXJ2aWNlczE2MDQG
A1UEAxMtcmVtb3RlLXNldHRpbmdzLmNvbnRlbnQtc2lnbmF0dXJlLm1vemlsbGEu
b3JnMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEeT/8OUNqKJ+3/ytnn3bQk96vvAhN
R+jrqvUa9BUDQiQiVYTRwt0v0cBm42ZlYbTSbMnO/5O/iBc/yww5kADDeJxtEoBR
/2Z4SLlK4rQtTqE4r5gnoe61yc6BEOeN5Z9go4GDMIGAMA4GA1UdDwEB/wQEAwIH
gDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAWgBRYxR116Nzt8ryAtGbr
6rke+PVUBDA4BgNVHREEMTAvgi1yZW1vdGUtc2V0dGluZ3MuY29udGVudC1zaWdu
YXR1cmUubW96aWxsYS5vcmcwCgYIKoZIzj0EAwMDaQAwZgIxALoBEwHh8G3O09KX
m1Ikegzizx3K9cGsHmw/MQSLvNOSxVH+ap/mRT1+fa/Y0xQHMAIxAPwgVu0kP5xY
p1ndI2eCj3d+JlVXD8GT+R/Rpn1OipPMZOZx+1TXhzslD+4Xi2oeIg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGZTCCBE2gAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wIhgPMjAyNDAyMDEwMDAwMDBaGA8yMjAwMTIwMzAwMDAw
MFowfTELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24x
LzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNl
MR8wHQYDVQQDExZyb290LWNhLXByb2R1Y3Rpb24tYW1vMIICIDANBgkqhkiG9w0B
AQEFAAOCAg0AMIICCAKCAgEAtLth11268Mt+vjD3in+Y4KAEjHzDc+5iVgXnCYL5
U3+IRyWy8zD7CFGrsyPRhKS3x3WesM0shTm+ADPg9ZsQFobmSdzAwCTn9wdUbOkK
Kx65fKqpTbTxqnqZ6TSXC6OybEqqhNzVJu9jIKiB0YE0bKlLPuyyDxnu9utlPjf0
9Cz2FS3uK2dkQx6GmYWGO2vfuPZhziP4NmBQfvcmYxPl3aZU9pAYAOD/HW+4uyNL
SIuG9AdDesvTIS/gkWScsXRXtsAcpCV9eC7IXirDNWsx42Tuekija1vFQCUy5KUc
QprIk69PH5z8gypmnmdAbbLoInHYqXGaV64iBprGWyNdqucrsI0hC3ZA1elGo6Np
/tsLObl6z9+Nl+9VoloQv3ReXc9SyrYwXZlJMWkDDj/7obVxCga2aNaLpw0UMdY+
/kpEOARMIwd0hLa+1w1hjnDiJKCWVjwAnwSwtzyQgVo0wMgZbndAuZ9wsva3oAAJ
ziKiNbdehlNpWkYe3pSe4D0TYEIMC13mXBccOsL8ohHJgozhEOjzPFEI7YTrCpbM
zIZSsL48jhg6M7ZKkgcv7/gLMezltkO65VXymqy9JkRGXUjH6Mt804LTFQjNL4TZ
es3L3+RzTaKaBHYOcrl6NnIWdadSfqvOm9BuciUTHk9vojlWNhEN+7R66lFEZ3As
uLsCAQOjge0wgeowDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0l
AQH/BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFLO86lh0q+FueCqyq5wjHqhjLJe3
MIGSBgNVHSMEgYowgYehgYGkfzB9MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96
aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlv
biBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1h
bW+CAQEwDQYJKoZIhvcNAQEMBQADggIBAAAJuN23qDiyAZ8y9DhqTfIfdYBXC7jg
f7p5DNCj6mcfLxCMLuSvLljYWm0IfHYs5W0lnQgm8+N0m3SAjQd18AzWfXNklFjZ
1EcP8MRU/keFEk9SmeHZhP916jQfqQvB45w4QwPcJG0nPkWsYzceqD3uL5g2g4Jg
gk+WYWmtE4eeM2BX6cT0itMErYKWei3SF09TdrCX+XpHMixg4nnDdsGe9wxc8F/o
diQ48f/7AZo06moMyZvIH4PPcVt0osAU18fLO0RrVJkupMraxbM1XXL1UwJlyV+p
kvJutX2xBB1f1BA3xPl3NlQneaLIm3JFsw0r7t0z0n1shC6xCi4+t3Fh6Z38CnbS
WwAe5rA2OCQYMjsehxRK9BhmDCG8U65GVd9t8nV4iEJFTrjntBDEFtVD5s4Qnlyv
OUrWd2du4dLCs+WW2E6+R7jZtrsIqFD6qwCLqcgBgC9CM9UgHeUBOixmZLBKCNDE
N1sRkmcVwXcCl5btdgVVq74Mgsd38xsmYuFoMi6nbDLllm6T2ql8LZExyX2i/vo0
pxhEVRaFwj1J1r3TRNXksjdqFcgpNCMf2FRbjDGtVLXRVG0DCCGRayigKgdH78qM
HpdXrbaTDFsfMLTAMnGFnqOZMuMobNJS5M6/vqdepoC8L7xmI5dQgW8YGyymr8DP
gchMof0tylgn
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

var normandyDev2021Roothash = []string{`4C:35:B1:C3:E3:12:D9:55:E7:78:ED:D0:A7:E7:8A:38:83:04:EF:01:BF:FA:03:29:B2:46:9F:3C:C5:EC:36:04`}

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
