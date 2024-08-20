package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer/apk2"
	"github.com/mozilla-services/autograph/signer/contentsignature"
	"github.com/mozilla-services/autograph/signer/genericrsa"
	"github.com/mozilla-services/autograph/signer/gpg2"
	"github.com/mozilla-services/autograph/signer/mar"
	"github.com/mozilla-services/autograph/signer/xpi"
	csigverifier "github.com/mozilla-services/autograph/verifier/contentsignature"

	"go.mozilla.org/hawk"
)

type requestType int

const (
	requestTypeNone = iota
	requestTypeData
	requestTypeHash
	requestTypeFile
	requestTypeFiles
)

type coseAlgs []string

func (i *coseAlgs) String() string {
	return ""
}

func (i *coseAlgs) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func urlToRequestType(url string) requestType {
	if strings.HasSuffix(url, "/sign/data") {
		return requestTypeData
	} else if strings.HasSuffix(url, "/sign/hash") {
		return requestTypeHash
	} else if strings.HasSuffix(url, "/sign/file") {
		return requestTypeFile
	} else if strings.HasSuffix(url, "/sign/files") {
		return requestTypeFiles
	}
	log.Fatalf("Unrecognized request type for url %q", url)
	return requestTypeNone
}

func main() {
	var (
		userid, pass, data, hash, url, infile, outfile, outkeyfile, outFilesPrefix, keyid, cn, pk7digest, rootPath, verificationTimeInput string
		iter, maxworkers, sa                                                                                                              int
		debug, listKeyIDs, noVerify                                                                                                       bool
		err                                                                                                                               error
		requests                                                                                                                          []formats.SignatureRequest
		algs                                                                                                                              coseAlgs
		verificationTime                                                                                                                  time.Time
	)
	flag.Usage = func() {
		fmt.Print("autograph-client - command line client to the autograph service\n\n")
		flag.PrintDefaults()
		fmt.Print(`
examples:

* pretty print keyids for a user to stdout
	$ go run client.go -listkeyids -u alice

* sign an APK, returns a signed APK
	$ go run client.go -f signed.apk -o test.apk -k testapp-android
	$ /opt/android-sdk/build-tools/27.0.3/apksigner verify -v test.apk
	Verifies
	Verified using v1 scheme (JAR signing): true
	Verified using v2 scheme (APK Signature Scheme v2): false
	Number of signers: 1

* sign an APK, returns a signed APK without compressing files in the ZIP that weren't already compressed
	$ go run client.go -f signed.apk -o test.apk -k testapp-android
	$ /opt/android-sdk/build-tools/27.0.3/apksigner verify -v test.apk
	Verifies
	Verified using v1 scheme (JAR signing): true
	Verified using v2 scheme (APK Signature Scheme v2): false
	Number of signers: 1
        4
        $ zipinfo ~/signed.apk | grep stor | wc -l
        326

* issue a content signature on a hash, returns a CS header string:
	$ echo -en "Content-Signature:\0\0foo bar baz" | openssl dgst -sha256 -binary | openssl enc -base64
	$ go run client.go -a rniK3StMMdrWbXuJxVqEjALHR4cIp6mn3Coilj1kozk= -o testcs.txt
	$ cat testcs.txt
	keyid=appkey1;p384ecdsa=gf_X5JHv1KItwnpgGxmIdJ9KdjZ7EZMcleM-BTMGLnDuPpRvaGUdUDUg...

* sign an XPI, returns a PKCS7 detached signature:
	$ base64 -w 0 mozilla.sf
	U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUt...
	$ go run client.go -d U2lnbmF0dXJlLVZlcnNpb2...  -cn cariboumaurice -k webextensions-rsa -o detachedxpisig.pkcs7

* sign an XPI file:
        $ go run client.go -f unsigned.xpi -cn cariboumaurice -k webextensions-rsa -o signed.xpi

* sign an XPI file with SHA256 PKCS7 digest:
        $ go run client.go -f unsigned.xpi -cn cariboumaurice -k webextensions-rsa -pk7digest sha256 -o signed.xpi

* sign an XPI file with one or more COSE signatures and verify against roots in roots.pem at 2006-01-02T15:04:05Z:
	$ go run client.go -f unsigned.xpi -cn cariboumaurice -k webextensions-rsa -o signed.xpi -c ES384 -c PS256 -r roots.pem -vt '2006-01-02T15:04:05Z'

* sign some data with gpg2:
        $ go run client.go -d $(echo 'hello' | base64) -k pgpsubkey -o /tmp/testsig.pgp -ko /tmp/testkey.asc

* sign some files with debsign and write signed output files to signed_foo_*:
        $ go run client.go -k pgpsubkey-debsign -outfilesprefix signed_foo_ foo.dsc foo.buildinfo foo.changes

* sign SHA1 hashed data with rsa pss:
        $ go run client.go -D -a $(echo hi | sha1sum -b | cut -d ' ' -f 1 | xxd -r -p | base64) -k dummyrsapss -o signed-hash.out -ko /tmp/testkey.pub

* issue an authenticode signature on a hash:
        $ go run client.go -D -a "$(echo foo | sha1sum -b | cut -d ' ' -f 1 | xxd -r -p | base64)" -k testauthenticode -o /tmp/sig.bin -ko /tmp/pub.key
`)
	}
	flag.StringVar(&userid, "u", "alice", "User ID")
	flag.StringVar(&pass, "p", "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu", "Secret passphrase")
	flag.StringVar(&data, "d", "base64(data)", "Base64 data to sign, will use the /sign/data endpoint")
	flag.StringVar(&hash, "a", "base64(sha256(data))", "Base64 hash to sign, will use the /sign/hash endpoint")
	flag.StringVar(&infile, "f", "/path/to/file", "Input file to sign, will use the /sign/file endpoint")
	flag.StringVar(&outfile, "o", ``, "Output file. If set, writes the signature or file to this location")
	flag.StringVar(&outkeyfile, "ko", ``, "Key Output file. If set, writes the public key to a file at this location")
	flag.StringVar(&outFilesPrefix, "outfilesprefix", `signed_`, "Prefix to use for output filenames when signing multiple files. Defaults to 'signed_'")
	flag.StringVar(&keyid, "k", ``, "Key ID to request a signature from a specific signer")
	flag.StringVar(&url, "t", `http://localhost:8000`, "target server, do not specific a URI or trailing slash")
	flag.IntVar(&iter, "i", 1, "number of signatures to request")
	flag.IntVar(&maxworkers, "m", 1, "maximum number of parallel workers")
	flag.StringVar(&cn, "cn", "", "when signing XPI, sets the CN to the add-on ID")
	flag.IntVar(&sa, "sa", 0, "when signing MAR hashes, sets the Signature Algorithm")
	flag.Var(&algs, "c", "a COSE Signature algorithm to sign an XPI with can be used multiple times")
	flag.StringVar(&pk7digest, "pk7digest", "", "an optional PK7 digest algorithm to use for XPI file signing, either 'sha1' (default) or 'sha256'.")
	flag.StringVar(&rootPath, "r", "/path/to/root.pem", "Path to a PEM file of root certificates")
	flag.StringVar(&verificationTimeInput, "vt", "", "Time to verify XPI signatures at in RFC3339 format. Defaults to at client invokation + 1 minute to account for time to transfer and sign the XPI")
	flag.BoolVar(&noVerify, "noverify", false, "Skip verifying successful responses. Default false.")
	flag.BoolVar(&listKeyIDs, "listkeyids", false, "List key IDs for the signer")

	flag.BoolVar(&debug, "D", false, "debug logs: show raw requests & responses")
	flag.Parse()

	if verificationTimeInput == "" {
		verificationTime = time.Now().UTC().Add(time.Minute)
		if debug {
			fmt.Printf("Using default verification time: %q\n", verificationTime)
		}
	} else {
		verificationTime = parseVerificationTime(verificationTimeInput)
		if debug {
			fmt.Printf("Using parsed verification time: %q\n", verificationTime)
		}
	}

	cli := getHTTPClient()
	if listKeyIDs {
		listKeyIDsForCurrentUser(cli, debug, url, userid, pass)
		os.Exit(0)
	}

	var (
		inputFiles []formats.SigningFile
		request    formats.SignatureRequest
	)
	if data != "base64(data)" {
		log.Printf("signing data %q", data)
		url = url + "/sign/data"
	} else if hash != "base64(sha256(data))" {
		log.Printf("signing hash %q", hash)
		url = url + "/sign/hash"
		data = hash
	} else if infile != "/path/to/file" {
		log.Printf("signing file %q", infile)
		url = url + "/sign/file"
		filebytes, err := os.ReadFile(infile)
		if err != nil {
			log.Fatal(err)
		}
		data = base64.StdEncoding.EncodeToString(filebytes)
	} else {
		log.Printf("signing files %q", flag.Args())
		url = url + "/sign/files"
		for _, inputFilename := range flag.Args() {
			inputFileBytes, err := os.ReadFile(inputFilename)
			if err != nil {
				log.Fatal(err)
			}
			inputFiles = append(inputFiles, formats.SigningFile{
				Name:    filepath.Base(inputFilename),
				Content: base64.StdEncoding.EncodeToString(inputFileBytes),
			})
		}
	}

	if strings.HasSuffix(url, "/sign/files") {
		request = formats.SignatureRequest{
			Files: inputFiles,
			KeyID: keyid,
		}
	} else {
		request = formats.SignatureRequest{
			Input: data,
			KeyID: keyid,
		}
	}
	// if signing an xpi, the CN, COSEAlgorithms, and PKCS7Digest are set in the options
	if cn != "" {
		if pk7digest == "" {
			pk7digest = "sha1"
		}
		request.Options = xpi.Options{
			ID:             cn,
			COSEAlgorithms: algs,
			PKCS7Digest:    pk7digest,
		}
	}
	// if signing a MAR hash, the Signature Algorithm is set in the options
	if sa > 0 {
		request.Options = mar.Options{
			SigAlg: uint32(sa),
		}
	}

	requests = append(requests, request)
	reqBody, err := json.Marshal(requests)
	if err != nil {
		log.Fatal(err)
	}

	var roots *x509.CertPool
	if rootPath != "/path/to/root.pem" {
		roots = x509.NewCertPool()
		rootContent, err := os.ReadFile(rootPath)
		if err != nil {
			log.Fatalf("failed to read roots from path %s: %s", rootPath, err)
		}
		ok := roots.AppendCertsFromPEM(rootContent)
		if !ok {
			log.Fatalf("failed to add root certs to pool")
		}
	}

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
			rdr := bytes.NewReader(reqBody)
			req, err := http.NewRequest("POST", url, rdr)
			if err != nil {
				log.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			authheader := getAuthHeader(req, userid, pass, sha256.New, fmt.Sprintf("%d", time.Now().Nanosecond()), "application/json", reqBody)
			req.Header.Set("Authorization", authheader)
			if debug {
				fmt.Printf("DEBUG: sending request\nDEBUG: %+v\nDEBUG: %s\n", req, reqBody)
			}
			resp, err := cli.Do(req)
			if err != nil || resp == nil {
				log.Fatal(err)
			}
			if debug {
				fmt.Printf("DEBUG: received response\nDEBUG: %+v\n", resp)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if debug {
				fmt.Printf("DEBUG: %s\n", body)
			}
			if resp.StatusCode != http.StatusCreated {
				log.Fatalf("%s %s", resp.Status, body)
			}
			// verify that we got a proper signature response, with a valid signature
			var responses []formats.SignatureResponse
			err = json.Unmarshal(body, &responses)
			if err != nil {
				log.Fatal(err)
			}
			if len(requests) != len(responses) {
				log.Fatalf("sent %d signature requests and got %d responses, something's wrong", len(requests), len(responses))
			}
			reqType := urlToRequestType(url)
			for i, response := range responses {
				var (
					input       []byte
					signedFiles []formats.SigningFile
					sigStatus   bool
					sigData     []byte
				)
				if reqType != requestTypeFiles {
					input, err = base64.StdEncoding.DecodeString(requests[i].Input)
					if err != nil {
						log.Fatal(err)
					}
				}
				switch response.Type {
				case contentsignature.Type:
					if !noVerify {
						sigStatus = verifyContentSignature(input, response, req.URL.RequestURI())
					}
					sig, err := csigverifier.Unmarshal(response.Signature)
					if err != nil {
						log.Fatal(err)
					}
					var sigStr string
					if response.X5U != "" {
						sigStr = "x5u=" + response.X5U + ";"
					} else {
						sigStr = "keyid=" + response.SignerID + ";"
					}
					sigStr += sig.Mode + "=" + response.Signature + "\n"
					sigData = []byte(sigStr)
				case xpi.Type:
					if !noVerify {
						sigStatus = verifyXPI(input, request, response, reqType, roots, verificationTime)
					}
					switch reqType {
					case requestTypeData:
						sigData, err = base64.StdEncoding.DecodeString(response.Signature)
					case requestTypeFile:
						sigData, err = base64.StdEncoding.DecodeString(response.SignedFile)
					default:
						err = fmt.Errorf("Cannot decode signature data for request type %v", reqType)
					}
					if err != nil {
						log.Fatal(err)
					}
				case apk2.Type:
					sigData, err = base64.StdEncoding.DecodeString(response.SignedFile)
					if err != nil {
						log.Fatal(err)
					}
					if !noVerify {
						sigStatus = verifyAPK2(sigData)
					}
				case mar.Type:
					if !noVerify {
						sigStatus = verifyMAR(input)
					}
					sigData, err = base64.StdEncoding.DecodeString(response.SignedFile)
					if err != nil {
						log.Fatal(err)
					}
				case genericrsa.Type:
					if !noVerify {
						err = genericrsa.VerifyGenericRsaSignatureResponse(input, response)
						if err != nil {
							log.Fatal(err)
						}
						sigStatus = true
					}
					sigData, err = base64.StdEncoding.DecodeString(response.Signature)
					if err != nil {
						log.Fatal(err)
					}
				case gpg2.Type:
					if reqType == requestTypeFiles {
						// TODO: implement verify pgp clearsigned
						if !noVerify {
							sigStatus = true
						}
						signedFiles = response.SignedFiles
					} else {
						if !noVerify {
							sigStatus = verifyPGP(input, response.Signature, response.PublicKey)
						}
						sigData = []byte(response.Signature)
					}
				default:
					log.Fatalf("unsupported signature type: %s", response.Type)
				}
				if !noVerify {
					if sigStatus {
						log.Printf("signature %d from signer %q passes", i, response.SignerID)
					} else {
						log.Fatalf("response %d from signer %q does not pass!", i, response.SignerID)
					}
				}
				if outfile != "" {
					err = os.WriteFile(outfile, sigData, 0644)
					if err != nil {
						log.Fatal(err)
					}
					log.Println("response written to", outfile)
				}
				if outkeyfile != "" {
					err = os.WriteFile(outkeyfile, []byte(response.PublicKey), 0644)
					if err != nil {
						log.Fatal(err)
					}
					log.Println("public key written to", outkeyfile)
				}
				for _, signedFile := range signedFiles {
					signedOutputFilename := fmt.Sprintf("%s%s", outFilesPrefix, signedFile.Name)
					signedFileBytes, err := base64.StdEncoding.DecodeString(signedFile.Content)
					if err != nil {
						log.Fatal(err)
					}
					err = os.WriteFile(signedOutputFilename, signedFileBytes, 0644)
					if err != nil {
						log.Fatal(err)
					}
					log.Printf("wrote signed file %s", signedOutputFilename)
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

func getHTTPClient() *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: false,
	}
	return &http.Client{Transport: tr}
}

func listKeyIDsForCurrentUser(cli *http.Client, debug bool, url, userid, pass string) {
	url = url + "/auths/" + userid + "/keyids"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Authorization", hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   userid,
			Key:  pass,
			Hash: sha256.New},
		0).RequestHeader())
	if debug {
		fmt.Printf("DEBUG: sending request\nDEBUG: %+v\n", req)
	}
	resp, err := cli.Do(req)
	if err != nil || resp == nil {
		log.Fatal(err)
	}
	if debug {
		fmt.Printf("DEBUG: received response\nDEBUG: %+v\n", resp)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if debug {
		fmt.Printf("DEBUG: %s\n", body)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s %s", resp.Status, body)
	}
	// pretty print output
	var keyIDs []string
	err = json.Unmarshal(body, &keyIDs)
	if err != nil {
		log.Fatalf("error unmarshaling JSON %q", err)
	}
	indentedJSON, err := json.MarshalIndent(keyIDs, "", "    ")
	if err != nil {
		log.Fatalf("error marshal indenting JSON %q", err)
	}
	fmt.Println(string(indentedJSON))
}

// parseVerificationTime parses an RFC3339 timestamp or exits
func parseVerificationTime(rfc3339Timestamp string) time.Time {
	parsed, err := time.Parse(time.RFC3339, rfc3339Timestamp)
	if err != nil {
		log.Fatalf("error parsing verification timestamp %q: %q", rfc3339Timestamp, err)
	}
	return parsed
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
func verifyContentSignature(input []byte, resp formats.SignatureResponse, endpoint string) bool {
	keyBytes, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := keyInterface.(*ecdsa.PublicKey)
	sig, err := csigverifier.Unmarshal(resp.Signature)
	if err != nil {
		log.Fatal(err)
	}
	if endpoint == "/sign/data" {
		return sig.VerifyData(input, pubKey)
	}
	return sig.VerifyHash(input, pubKey)
}

func verifyXPI(input []byte, req formats.SignatureRequest, resp formats.SignatureResponse, reqType requestType, roots *x509.CertPool, verificationTime time.Time) bool {
	switch reqType {
	case requestTypeData:
		sig, err := xpi.Unmarshal(resp.Signature, input)
		if err != nil {
			log.Fatal(err)
		}
		err = sig.VerifyWithChain(nil)
		if err != nil {
			log.Fatal(err)
		}
		return true
	case requestTypeFile:
		signedFile, err := base64.StdEncoding.DecodeString(resp.SignedFile)
		if err != nil {
			log.Fatal(err)
		}
		err = xpi.VerifySignedFile(signedFile, roots, req.Options.(xpi.Options), verificationTime)
		if err != nil {
			log.Fatal(err)
		}
		return true
	default:
		return false
	}
}

func verifyMAR(signedMAR []byte) bool {
	log.Println("mar verification is not implemented, skipping")
	return true
}

func verifyPGP(input []byte, signature string, pubkey string) bool {
	log.Println("pgp verification is not implemented, skipping")
	return true
}

func verifyAPK2(input []byte) bool {
	log.Println("apk2 verification is not implemented, skipping")
	return true
}
