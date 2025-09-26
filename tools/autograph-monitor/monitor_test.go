package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mozilla-services/autograph/formats"
)

func TestGoldenPath(t *testing.T) {
	firstRsaKey := generateRSAKey(t)
	secondRsaKey := generateRSAKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__monitor__", func(w http.ResponseWriter, r *http.Request) {
		respBytes1, err := signatureRespForGenericaRSA("first", firstRsaKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respBytes2, err := signatureRespForGenericaRSA("second", secondRsaKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, err = w.Write(respBytes1)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = w.Write(respBytes2)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	monitorEndpoint, err := rawAutographURLToMonitorEndpoint(server.URL)
	if err != nil {
		t.Fatalf("failed to turn httptest server %#v into the endpoint url : %s", server.URL, err)
	}

	conf := &configuration{
		origAutographURL: server.URL,
		requestURL:       monitorEndpoint,
		monitoringKey:    "fakenotused",
		truststore:       x509.NewCertPool(),
	}
	err = Handler(conf, server.Client())
	if err != nil {
		t.Errorf("handler error: %v", err)
	}
}

func TestNormalizeAutographURL(t *testing.T) {
	testcases := map[string][]string{
		"https://golden.com/__monitor__":    {"https://golden.com", "https://golden.com/", "https://golden.com//"},
		"https://port.com:7890/__monitor__": {"https://port.com:7890", "https://port.com:7890/", "https://port.com:7890//"},
		"http://testing.com/__monitor__":    {"http://testing.com", "http://testing.com/", "http://testing.com//"},
	}

	for expectedURL, origURLs := range testcases {
		for _, tc := range origURLs {
			t.Run(tc+"->"+expectedURL, func(t *testing.T) {
				out, err := rawAutographURLToMonitorEndpoint(tc)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if out != expectedURL {
					t.Errorf("want %#v, got %#v", expectedURL, out)
				}
			})
		}
	}

	errorcases := []string{"golden.com", "golden.com/", "port.com:7890", "port.com:7890/"}
	for _, tc := range errorcases {
		t.Run("error-"+tc, func(t *testing.T) {
			_, err := rawAutographURLToMonitorEndpoint(tc)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

type rsaOption struct {
	// crypto.Hash is just a uint, so the json.Marshal/Unmarshal calls work,
	// but it's a lil sketchy.
	crypto.Hash
}

func (r *rsaOption) HashFunc() crypto.Hash {
	return r.Hash
}

func signatureRespForGenericaRSA(signerID string, key *rsa.PrivateKey) ([]byte, error) {
	rsaOpt := &rsaOption{Hash: crypto.SHA256}
	hash := rsaOpt.Hash.HashFunc().New()
	_, err := hash.Write([]byte(inputdata))
	if err != nil {
		return nil, err
	}

	sig, err := key.Sign(rand.Reader, hash.Sum(nil), rsaOpt)
	if err != nil {
		return nil, err
	}
	marshalled, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	resp := &formats.SignatureResponse{
		SignerID:   signerID,
		Type:       "genericrsa",
		Signature:  base64.StdEncoding.EncodeToString(sig),
		PublicKey:  base64.StdEncoding.EncodeToString(marshalled),
		Mode:       "pkcs15",
		SignerOpts: rsaOpt,
	}
	return json.Marshal(resp)
}
