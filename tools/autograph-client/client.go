package main

import (
	"bytes"
	"crypto/ecdsa"
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
	"net/http"
	"time"

	"go.mozilla.org/autograph/signer/apk"
	"go.mozilla.org/autograph/signer/contentsignature"
	"go.mozilla.org/autograph/signer/xpi"
	"go.mozilla.org/hawk"
)

type signaturerequest struct {
	Input string `json:"input"`
	KeyID string `json:"keyid"`
}

type signatureresponse struct {
	Ref       string `json:"ref"`
	Type      string `json:"type"`
	SignerID  string `json:"signer_id"`
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature"`
}

func main() {
	var (
		userid, pass, sigreq, url string
		iter, maxworkers          int
		debug                     bool
	)
	flag.StringVar(&userid, "u", "alice", "User ID")
	flag.StringVar(&pass, "p", "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu", "Secret passphrase")
	flag.StringVar(&sigreq, "r", `[{"input": "Y2FyaWJvdW1hdXJpY2UK"}]`, "JSON signing request")
	flag.StringVar(&url, "t", `http://localhost:8000/sign/data`, "signing api URL")
	flag.IntVar(&iter, "i", 1, "number of signatures to request")
	flag.IntVar(&maxworkers, "m", 1, "maximum number of parallel workers")
	flag.BoolVar(&debug, "D", false, "debug logs: show raw requests & responses")
	flag.Parse()

	// verify format of signature request
	var requests []signaturerequest
	err := json.Unmarshal([]byte(sigreq), &requests)
	if err != nil {
		log.Fatal(err)
	}
	if len(requests) == 0 {
		log.Fatalf("no signature request found in input: %s", sigreq)
	}
	tr := &http.Transport{
		DisableKeepAlives: false,
	}
	cli := &http.Client{Transport: tr}

	workers := 0
	for i := 0; i < iter; i++ {
		for {
			if workers < maxworkers {
				break
			}
			time.Sleep(time.Second)
		}
		workers++
		go func() {
			// prepare the http request, with hawk token
			rdr := bytes.NewReader([]byte(sigreq))
			req, err := http.NewRequest("POST", url, rdr)
			if err != nil {
				log.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			authheader := getAuthHeader(req, userid, pass, sha256.New, fmt.Sprintf("%d", time.Now().Nanosecond()), "application/json", []byte(sigreq))
			req.Header.Set("Authorization", authheader)
			if debug {
				fmt.Printf("DEBUG: sending request\nDEBUG: %+v\nDEBUG: %s\n", req, sigreq)
			}
			resp, err := cli.Do(req)
			if err != nil || resp == nil {
				log.Fatal(err)
			}
			if debug {
				fmt.Printf("DEBUG: received response\nDEBUG: %+v\n", resp)
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if debug {
				fmt.Printf("DEBUG: %s\n", body)
			}

			// verify that we got a proper signature response, with a valid signature
			var responses []signatureresponse
			err = json.Unmarshal(body, &responses)
			if err != nil {
				log.Fatal(err)
			}
			if len(requests) != len(responses) {
				log.Fatalf("sent %d signature requests and got %d responses, something's wrong", len(requests), len(responses))
			}
			for i, response := range responses {
				input, err := base64.RawURLEncoding.DecodeString(requests[i].Input)
				if err != nil {
					log.Fatal(err)
				}
				var sigStatus bool
				switch response.Type {
				case contentsignature.Type:
					sigStatus = verifyContentSignature(input, response, req.URL.RequestURI())
				case xpi.Type:
					sigStatus = verifyXPI(input, response)
				case apk.Type:
					sigStatus = verifyAPK(input, response)
				default:
					log.Fatal("unsupported signature type", response.Type)
				}
				if sigStatus {
					log.Printf("signature %d from signer %q passes", i, response.SignerID)
				} else {
					log.Fatalf("response %d from signer %q does not pass!", i, response.SignerID)
				}
			}
			workers--
		}()
	}
	for {
		if workers <= 0 {
			break
		}
		time.Sleep(time.Second)
	}
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
func verifyContentSignature(input []byte, resp signatureresponse, endpoint string) bool {
	keyBytes, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := keyInterface.(*ecdsa.PublicKey)
	if endpoint == "/sign/data" {
		var templated []byte
		templated = make([]byte, len("Content-Signature:\x00")+len(input))
		copy(templated[:len("Content-Signature:\x00")], []byte("Content-Signature:\x00"))
		copy(templated[len("Content-Signature:\x00"):], input)

		var md hash.Hash
		switch pubKey.Params().Name {
		case "P-256":
			md = sha256.New()
		case "P-384":
			md = sha512.New384()
		case "P-521":
			md = sha512.New()
		default:
			log.Fatalf("unsupported curve algorithm %q", pubKey.Params().Name)
		}
		md.Write(templated)
		input = md.Sum(nil)
	}
	sig, err := contentsignature.Unmarshal(resp.Signature)
	if err != nil {
		log.Fatal(err)
	}
	return ecdsa.Verify(pubKey, input, sig.R, sig.S)
}

func verifyXPI(input []byte, resp signatureresponse) bool {
	sig, err := xpi.Unmarshal(resp.Signature, input)
	if err != nil {
		log.Fatal(err)
	}
	err = sig.VerifyWithChain(nil)
	if err != nil {
		log.Fatal(err)
	}
	return true
}

func verifyAPK(input []byte, resp signatureresponse) bool {
	log.Println(resp)
	sig, err := apk.Unmarshal(resp.Signature, input)
	if err != nil {
		log.Fatal(err)
	}
	err = sig.Verify()
	if err != nil {
		log.Fatal(err)
	}
	return true
}
