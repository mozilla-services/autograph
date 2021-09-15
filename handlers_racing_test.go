//go:build !race
// +build !race

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer/apk2"
	"github.com/mozilla-services/autograph/signer/contentsignature"
	"github.com/mozilla-services/autograph/signer/mar"
	"github.com/mozilla-services/autograph/signer/xpi"

	margo "go.mozilla.org/mar"
)

func TestSignaturePass(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		endpoint          string
		signaturerequests []formats.SignatureRequest
	}{
		{
			// Sign hash with Content Signature
			"/sign/hash",
			[]formats.SignatureRequest{
				// request signature of a precomputed sha384 hash
				formats.SignatureRequest{
					Input: "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d",
					KeyID: "appkey1",
				},
			},
		},
		{
			// Sign a regular add-on
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUtRGlnZXN0LU1hbmlmZXN0OiA3d3RFNTF2bW00NlZQRmEvNkF0NWZ3PT0KU0hBMS1EaWdlc3QtTWFuaWZlc3Q6IEZMZEFIZHQvVjdFVHozK0JMUUtHcFFBenoyRT0KCg==",
					KeyID: "webextensions-rsa",
					Options: map[string]string{
						"id": "test@example.net",
					},
				},
			},
		},
		{
			// Sign an extension
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUtRGlnZXN0LU1hbmlmZXN0OiA3d3RFNTF2bW00NlZQRmEvNkF0NWZ3PT0KU0hBMS1EaWdlc3QtTWFuaWZlc3Q6IEZMZEFIZHQvVjdFVHozK0JMUUtHcFFBenoyRT0KCg==",
					KeyID: "extensions-ecdsa",
					Options: map[string]string{
						"id": "test@example.net",
					},
				},
			},
		},
		{
			// Sign data with Content-Signature
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "PCFET0NUWVBFIEhUTUw+CjxodG1sPgo8IS0tIGh0dHBzOi8vYnVnemlsbGEubW96aWxsYS5vcmcvc2hvd19idWcuY2dpP2lkPTEyMjY5MjggLS0+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8dGl0bGU+VGVzdHBhZ2UgZm9yIGJ1ZyAxMjI2OTI4PC90aXRsZT4KPC9oZWFkPgo8Ym9keT4KICBKdXN0IGEgZnVsbHkgZ29vZCB0ZXN0cGFnZSBmb3IgQnVnIDEyMjY5Mjg8YnIvPgo8L2JvZHk+CjwvaHRtbD4K",
					KeyID: "appkey2",
				},
			},
		},
		{
			// Sign an APK file
			"/sign/file",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "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",
					KeyID: "testapp-android",
				},
			},
		},
		{
			// Sign MAR data
			"/sign/data",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					Input: "Y2FyaWJvdW1hdXJpY2U=",
					KeyID: "testmar",
				},
			},
		},
		{
			// Sign a MAR file
			"/sign/file",
			[]formats.SignatureRequest{
				formats.SignatureRequest{
					// Input is the base64 of miniMarB from the mar signer unit tests
					Input: "TUFSMQAAAX0AAAAAAAABlgAAAAIAAAACAAABACDExrLgT1Lc1TbLUiKbIVxQl60L6ATvYe6L6JwewAbVSjhEUCGMQ0OK1TmKi18GGijNxaf/uU7Lm/RTyvm0VL7gcODm/pogDmRttf+rc2UfX7nthPxCgB/oOj7fXqDwYpiBPNSSHMIATUb7fnRRHqVTdqhkQZ2RqQsyKL7O6D/bN62EHmVTnn5LbYqYnDLhp+bEVGPo9ETsUpSk7XlFq3v96blLi4Iazm4LyPUXtQmixNwe6OOGpS+ZqobGAtooe7nPPC0Q/kqqKKQmcwCyTP/+lD1Vk7JXbDyGzYj9f9Cloq8PH7gyxOmNvwfHxMU95Jw/ExdFUDdK6QW7UPRTx7AAAAADAAAAQMSHgnYz95K8msSv6YA6IWRfT99ig0W74KDl0QvM0Ti+BRvI7FSmjjt4QOfVHRDko31NuVa2sUCo/PibauLI7GwAAAAAYWFhYWFhYWFhYWFhYWFhYWFhYWFhAAAAFQAAAWgAAAAVAAACWC9mb28vYmFyAA==",
					KeyID: "testmar",
				},
			},
		},
	}
	for i, testcase := range TESTCASES {
		userid := conf.Authorizations[0].ID
		body, err := json.Marshal(testcase.signaturerequests)
		if err != nil {
			t.Fatal(err)
		}
		rdr := bytes.NewReader(body)
		req, err := http.NewRequest("POST",
			"http://foo.bar"+testcase.endpoint,
			rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		// generate a hawk header for the request
		testAuth, err := ag.getAuthByID(userid)
		if err != nil {
			t.Fatal(err)
		}

		authheader := getAuthHeader(req,
			testAuth.ID,
			testAuth.Key,
			sha256.New,
			id(),
			"application/json",
			body)
		req.Header.Set("Authorization", authheader)

		// send the request to the handler
		w := httptest.NewRecorder()
		ag.handleSignature(w, req)
		if w.Code != http.StatusCreated || w.Body.String() == "" {
			t.Fatalf("failed with %d: %s; request was: %+v", w.Code, w.Body.String(), req)
		}

		// parse the response
		var responses []formats.SignatureResponse
		err = json.Unmarshal(w.Body.Bytes(), &responses)
		if err != nil {
			t.Fatal(err)
		}

		// we should have received the same number of responses as we sent requests
		if len(responses) != len(testcase.signaturerequests) {
			t.Fatalf("in test case %d, failed to receive as many responses (%d) as we sent requests (%d)",
				i, len(responses), len(testcase.signaturerequests))
		}

		// verify the signature in each response
		for j, response := range responses {
			switch response.Type {
			case contentsignature.Type:
				err = verifyContentSignatureResponse(
					testcase.signaturerequests[j].Input,
					response,
					testcase.endpoint)
			case xpi.Type:
				err = verifyXPISignature(testcase.signaturerequests[j].Input, response.Signature)
			case apk2.Type:
				if req.URL.RequestURI() == "/sign/data" {
					// ok this is a bit of a hack but since apk signatures are really just pkcs7 we can
					// reuse the xpi verification code here...
					err = verifyAPKManifestSignature(testcase.signaturerequests[j].Input, response.Signature)
				} else {
					signedAPK, _ := base64.StdEncoding.DecodeString(response.SignedFile)
					err = verifyAPKSignature(signedAPK)
				}
			case mar.Type:
				switch req.URL.RequestURI() {
				case "/sign/file":
					// use the margo pkg to calculate the signable block of the mar file
					// as input for the signature verification
					rawInput, err := base64.StdEncoding.DecodeString(testcase.signaturerequests[j].Input)
					if err != nil {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v failed to decode input",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					if !bytes.Equal(miniMarB, rawInput) {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v decoded input did not match expected input",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					var marFile margo.File
					err = margo.Unmarshal(rawInput, &marFile)
					if err != nil {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v failed to unmarshal mar sig",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					rawKey, err := base64.StdEncoding.DecodeString(response.PublicKey)
					if err != nil {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					pubkey, err := x509.ParsePKIXPublicKey(rawKey)
					if err != nil {
						t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v",
							i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
					}
					err = marFile.VerifySignature(pubkey)
					// TODO: figure out why testcase 6 fails with "error verifying mar signature 'no valid signature found'"
					if err == nil {
						t.Fatalf("in test case %d on endpoint %q, did not error verifying mar signature as expected",
							i, testcase.endpoint)
					}
				default:
					err = verifyMARSignature(testcase.signaturerequests[j].Input, response.Signature, response.PublicKey, margo.SigAlgRsaPkcs1Sha384)
				}
			default:
				err = fmt.Errorf("unknown signature type %q", response.Type)
			}
			if err != nil {
				t.Fatalf("in test case %d on endpoint %q, error '%v' in response %d;\nrequest was: %+v\nresponse was: %+v",
					i, testcase.endpoint, err, j, testcase.signaturerequests[j], response)
			}
		}
	}
}

var miniMarB = []byte("\x4D\x41\x52\x31\x00\x00\x01\x7D\x00\x00\x00\x00\x00\x00\x01\x96" +
	"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x01\x00\x20\xC4\xC6\xB2" +
	"\xE0\x4F\x52\xDC\xD5\x36\xCB\x52\x22\x9B\x21\x5C\x50\x97\xAD\x0B" +
	"\xE8\x04\xEF\x61\xEE\x8B\xE8\x9C\x1E\xC0\x06\xD5\x4A\x38\x44\x50" +
	"\x21\x8C\x43\x43\x8A\xD5\x39\x8A\x8B\x5F\x06\x1A\x28\xCD\xC5\xA7" +
	"\xFF\xB9\x4E\xCB\x9B\xF4\x53\xCA\xF9\xB4\x54\xBE\xE0\x70\xE0\xE6" +
	"\xFE\x9A\x20\x0E\x64\x6D\xB5\xFF\xAB\x73\x65\x1F\x5F\xB9\xED\x84" +
	"\xFC\x42\x80\x1F\xE8\x3A\x3E\xDF\x5E\xA0\xF0\x62\x98\x81\x3C\xD4" +
	"\x92\x1C\xC2\x00\x4D\x46\xFB\x7E\x74\x51\x1E\xA5\x53\x76\xA8\x64" +
	"\x41\x9D\x91\xA9\x0B\x32\x28\xBE\xCE\xE8\x3F\xDB\x37\xAD\x84\x1E" +
	"\x65\x53\x9E\x7E\x4B\x6D\x8A\x98\x9C\x32\xE1\xA7\xE6\xC4\x54\x63" +
	"\xE8\xF4\x44\xEC\x52\x94\xA4\xED\x79\x45\xAB\x7B\xFD\xE9\xB9\x4B" +
	"\x8B\x82\x1A\xCE\x6E\x0B\xC8\xF5\x17\xB5\x09\xA2\xC4\xDC\x1E\xE8" +
	"\xE3\x86\xA5\x2F\x99\xAA\x86\xC6\x02\xDA\x28\x7B\xB9\xCF\x3C\x2D" +
	"\x10\xFE\x4A\xAA\x28\xA4\x26\x73\x00\xB2\x4C\xFF\xFE\x94\x3D\x55" +
	"\x93\xB2\x57\x6C\x3C\x86\xCD\x88\xFD\x7F\xD0\xA5\xA2\xAF\x0F\x1F" +
	"\xB8\x32\xC4\xE9\x8D\xBF\x07\xC7\xC4\xC5\x3D\xE4\x9C\x3F\x13\x17" +
	"\x45\x50\x37\x4A\xE9\x05\xBB\x50\xF4\x53\xC7\xB0\x00\x00\x00\x03" +
	"\x00\x00\x00\x40\xC4\x87\x82\x76\x33\xF7\x92\xBC\x9A\xC4\xAF\xE9" +
	"\x80\x3A\x21\x64\x5F\x4F\xDF\x62\x83\x45\xBB\xE0\xA0\xE5\xD1\x0B" +
	"\xCC\xD1\x38\xBE\x05\x1B\xC8\xEC\x54\xA6\x8E\x3B\x78\x40\xE7\xD5" +
	"\x1D\x10\xE4\xA3\x7D\x4D\xB9\x56\xB6\xB1\x40\xA8\xFC\xF8\x9B\x6A" +
	"\xE2\xC8\xEC\x6C\x00\x00\x00\x00\x61\x61\x61\x61\x61\x61\x61\x61" +
	"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x00\x00\x00" +
	"\x15\x00\x00\x01\x68\x00\x00\x00\x15\x00\x00\x02\x58\x2F\x66\x6F" +
	"\x6F\x2F\x62\x61\x72\x00")
