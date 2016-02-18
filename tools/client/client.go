package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mozilla-services/hawk-go"
)

type signaturerequest struct {
	Template string `json:"template"`
	HashWith string `json:"hashwith"`
	Input    string `json:"input"`
	KeyID    string `json:"keyid"`
}

type signatureresponse struct {
	Ref         string          `json:"ref"`
	Certificate certificate     `json:"certificate"`
	Signatures  []signaturedata `json:"signatures"`
}
type certificate struct {
	X5u           string `json:"x5u,omitempty"`
	EncryptionKey string `json:"encryptionkey,omitempty"`
}
type signaturedata struct {
	Encoding  string `json:"encoding,omitempty"`
	Signature string `json:"signature,omitempty"`
	Hash      string `json:"hashalgorithm,omitempty"`
}

func main() {
	var (
		userid, pass, sigreq, url string
	)

	flag.StringVar(&userid, "u", "alice", "User ID")
	flag.StringVar(&pass, "p", "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu", "Secret passphrase")
	flag.StringVar(&sigreq, "r", `[{"input": "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`, "JSON signing request")
	flag.StringVar(&url, "t", `http://localhost:8000/signature`, "signing api URL")

	flag.Parse()

	// verify format of signature request
	var requests []signaturerequest
	err := json.Unmarshal([]byte(sigreq), &requests)
	if err != nil {
		log.Fatal(err)
	}
	if len(requests) == 0 {
		log.Fatal("no signature request found in input: %s", sigreq)
	}

	// prepare the http request, with hawk token
	rdr := bytes.NewReader([]byte(sigreq))
	req, err := http.NewRequest("POST", url, rdr)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	authheader := getAuthHeader(req, userid, pass, sha256.New, fmt.Sprintf("%d", time.Now().Nanosecond()), "application/json", []byte(sigreq))
	req.Header.Set("Authorization", authheader)

	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil || resp == nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	// verify that we got a proper signature response, with a valid signature
	var responses []signatureresponse
	err = json.Unmarshal(body, &responses)
	if err != nil {
		log.Fatal(err)
	}
	if len(requests) != len(responses) {
		log.Fatal("sent %d signature requests and got %d responses, something's wrong", len(requests), len(responses))
	}
	for i, response := range responses {
		if verify(requests[i], response) {
			fmt.Fprintf(os.Stderr, "response %d pass\n", i)
		} else {
			log.Fatal("response %d does not pass!", i)
		}
	}
	pretty, err := json.MarshalIndent(responses, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", pretty)
}

func getAuthHeader(req *http.Request, user, token string, hash func() hash.Hash, ext, contenttype string, payload []byte) string {
	auth := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   user,
			Key:  token,
			Hash: hash},
		0)
	auth.Ext = ext
	payloadhash := auth.PayloadHash(contenttype)
	payloadhash.Write(payload)
	auth.SetHash(payloadhash)
	return auth.RequestHeader()
}

// verify an ecdsa signature
func verify(req signaturerequest, resp signatureresponse) bool {
	data, err := fromBase64URL(req.Input)
	if err != nil {
		log.Fatal(err)
	}
	if req.HashWith != "" {
		// hash the input data with the provided algorithm
		data, err = digest(data, req.HashWith)
		if err != nil {
			log.Fatal(err)
		}
	}

	keyBytes, err := fromBase64URL(resp.Certificate.EncryptionKey)
	if err != nil {
		log.Fatal(err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := keyInterface.(*ecdsa.PublicKey)
	sigBytes, err := fromBase64URL(resp.Signatures[0].Signature)
	if err != nil {
		log.Fatal(err)
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sigBytes[:len(sigBytes)/2])
	s.SetBytes(sigBytes[len(sigBytes)/2:])
	if !ecdsa.Verify(pubKey, data, r, s) {
		return false
	}
	return true
}

func fromBase64URL(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(b64urlTob64(s))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func b64urlTob64(s string) string {
	// convert base64url characters back to regular base64 alphabet
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return s
}

func digest(data []byte, alg string) (hashed []byte, err error) {
	var md hash.Hash
	switch alg {
	case "sha1":
		md = sha1.New()
	case "sha256":
		md = sha256.New()
	case "sha384":
		md = sha512.New384()
	case "sha512":
		md = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
	md.Write(data)
	hashed = md.Sum(nil)
	return
}
