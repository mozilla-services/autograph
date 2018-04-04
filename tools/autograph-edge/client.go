package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"go.mozilla.org/autograph/signer/xpi"
	"go.mozilla.org/hawk"
)

type signaturerequest struct {
	Input   string `json:"input"`
	KeyID   string `json:"keyid"`
	Options interface{}
}

type signatureresponse struct {
	Ref        string `json:"ref"`
	Type       string `json:"type"`
	SignerID   string `json:"signer_id"`
	PublicKey  string `json:"public_key,omitempty"`
	Signature  string `json:"signature"`
	SignedFile string `json:"signed_file"`
	X5U        string `json:"x5u,omitempty"`
}

func callAutograph(auth authorization, body []byte) (signedBody []byte, err error) {
	var requests []signaturerequest
	request := signaturerequest{
		Input: base64.StdEncoding.EncodeToString(body),
		KeyID: auth.Signer,
	}
	if auth.AddonID != "" {
		request.Options = xpi.Options{ID: auth.AddonID}
	}
	requests = append(requests, request)
	reqBody, err := json.Marshal(requests)
	if err != nil {
		return
	}
	rdr := bytes.NewReader(reqBody)
	req, err := http.NewRequest(http.MethodPost, conf.URL, rdr)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// make the hawk auth header
	hawkAuth := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   auth.User,
			Key:  auth.Key,
			Hash: sha256.New},
		0)
	hawkAuth.Ext = fmt.Sprintf("%d", time.Now().Nanosecond())
	payloadhash := hawkAuth.PayloadHash("application/json")
	payloadhash.Write(reqBody)
	hawkAuth.SetHash(payloadhash)
	req.Header.Set("Authorization", hawkAuth.RequestHeader())

	// make the request
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return
	}
	if resp == nil {
		err = errAutographEmptyResponse
		return
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusCreated {
		err = errAutographBadStatusCode
		return
	}
	var responses []signatureresponse
	err = json.Unmarshal(respBody, &responses)
	if err != nil {
		return
	}
	if len(responses) != 1 {
		err = errAutographBadResponseCount
		return
	}
	return base64.StdEncoding.DecodeString(responses[0].SignedFile)
}
