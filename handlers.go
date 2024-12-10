// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/gorilla/mux"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer"
	log "github.com/sirupsen/logrus"
)

const (
	// MinNamedFiles is the minimum number of named files a single
	// multi-file signing request can include
	MinNamedFiles = 1

	// MaxNamedFiles is the maximum number of named files a single
	// multi-file signing request can include
	MaxNamedFiles = 32
)

// heartbeatConfig configures the heartbeat handler. It sets timeouts
// for each backing service to check.
//
// `hsmHeartbeatSignerConf` is determined added on boot in initHSM
type heartbeatConfig struct {
	HSMCheckTimeout time.Duration
	DBCheckTimeout  time.Duration

	// hsmSignerConf is the signer conf to use to check
	// HSM connectivity (set to the first signer with an HSM label
	// in initHSM) when it is non-nil
	hsmSignerConf *signer.Configuration
}

// hashSHA256AsHex returns the hex encoded string of the SHA256 sum
// the arg toHash bytes
func hashSHA256AsHex(toHash []byte) string {
	h := sha256.New()
	h.Write(toHash)
	return fmt.Sprintf("%X", h.Sum(nil))
}

func logSigningRequestFailure(sigreq formats.SignatureRequest, sigresp formats.SignatureResponse, rid, userid, inputHash string, inputHashes []string, starttime time.Time, err error) {
	log.WithFields(log.Fields{
		"rid":           rid,
		"options":       sigreq.Options,
		"mode":          sigresp.Mode,
		"ref":           sigresp.Ref,
		"type":          sigresp.Type,
		"signer_id":     sigresp.SignerID,
		"input_hash":    inputHash,
		"input_hashes":  inputHashes,
		"output_hash":   nil,
		"output_hashes": nil,
		"user_id":       userid,
		"t":             int32(time.Since(starttime) / time.Millisecond), //  request processing time in ms
	}).Info(fmt.Sprintf("signing operation failed with error: %v", err))
}

// rewriteLocalX5U checks for X5U certificate chains using the `file://` scheme
// and rewrites them to use the `/x5u/:keyid/` endpoint instead, which should
// mirror the contents of the signer's X5U location, and returns the updated URL.
//
// If the X5U certificate chain uses any other scheme, then the original URL is returned
// without change.
func rewriteLocalX5U(r *http.Request, keyid string, x5u string) string {
	parsedX5U, err := url.Parse(x5u)
	if err == nil && parsedX5U.Scheme == "file" {
		newX5U := url.URL{
			Scheme: "http",
			Host:   r.Host,
			Path:   path.Join("x5u", keyid, path.Base(parsedX5U.Path)),
		}
		return newX5U.String()
	}

	// Otherwise, return the X5U unmodified
	return x5u
}

// handleSignature endpoint accepts a list of signature requests in a HAWK authenticated POST request
// and calls the signers to generate signature responses.
func (a *autographer) handleSignature(w http.ResponseWriter, r *http.Request) {
	rid := getRequestID(r)
	starttime := getRequestStartTime(r)
	auth, userid, err := a.authorizeHeader(r)
	if err != nil {
		sendStatsErr := a.stats.Timing("hawk.authorize_header_failed", time.Since(starttime), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending hawk.authorize_header_failed: %s", sendStatsErr)
		}
		httpError(w, r, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpError(w, r, http.StatusBadRequest, "failed to read request body: %s", err)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		httpError(w, r, http.StatusBadRequest, "invalid content type, expected application/json")
		return
	}
	if len(body) < 10 {
		// it's impossible to have a valid request body smaller than 10 bytes
		httpError(w, r, http.StatusBadRequest, "empty or invalid request request body")
		return
	}
	if len(body) > 1048576000 {
		// the max body size is hardcoded to 1GB. Seriously, what are you trying to sign?
		httpError(w, r, http.StatusBadRequest, "request exceeds max size of 1GB")
		return
	}
	err = a.authorizeBody(auth, r, body)
	sendStatsErr := a.stats.Timing("authorize_finished", time.Since(starttime), nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending authorize_finished: %s", sendStatsErr)
	}
	if err != nil {
		httpError(w, r, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	var sigreqs []formats.SignatureRequest
	err = json.Unmarshal(body, &sigreqs)
	sendStatsErr = a.stats.Timing("body_unmarshaled", time.Since(starttime), nil, 1.0)
	if sendStatsErr != nil {
		log.Warnf("Error sending body_unmarshaled: %s", sendStatsErr)
	}
	if err != nil {
		httpError(w, r, http.StatusBadRequest, "failed to parse request body: %v", err)
		return
	}

	for i, sigreq := range sigreqs {
		if r.URL.RequestURI() == "/sign/files" {
			if sigreq.Input != "" {
				httpError(w, r, http.StatusBadRequest, "input should be empty in sign files signature request %d", i)
			}
			if sigreq.Files == nil {
				httpError(w, r, http.StatusBadRequest, "missing Files in sign files signature request %d", i)
			}
			if len(sigreq.Files) < MinNamedFiles {
				httpError(w, r, http.StatusBadRequest, "Did not receive enough files to sign. Need at least %d", MinNamedFiles)
				return
			} else if len(sigreq.Files) > MaxNamedFiles {
				httpError(w, r, http.StatusBadRequest, "Received too many files to sign (max is %d)", MaxNamedFiles)
				return
			}
		} else if sigreq.Input == "" {
			httpError(w, r, http.StatusBadRequest, "missing input in signature request %d", i)
		}
	}
	if a.debug {
		fmt.Printf("signature request\n-----------------\n%s\n", body)
	}
	sigReqsCount := len(sigreqs)
	sigresps := make([]formats.SignatureResponse, sigReqsCount)
	// Each signature requested in the http request body is processed individually.
	// For each, a signer is looked up, and used to compute a raw signature
	// the signature is then encoded appropriately, and added to the response slice
	for i, sigreq := range sigreqs {
		var (
			input                     []byte
			unsignedNamedFiles        []signer.NamedUnsignedFile
			sig                       signer.Signature
			signedfile                []byte
			signedfiles               []signer.NamedSignedFile
			inputHash, outputHash     string
			inputHashes, outputHashes []string
		)

		if r.URL.RequestURI() == "/sign/files" {
			for i, inputFile := range sigreq.Files {
				log.Debugf("base64 decoding file %d", i)
				unsignedNamedFile, err := signer.NewNamedUnsignedFile(inputFile)
				if err != nil {
					httpError(w, r, http.StatusBadRequest, "%q", err)
					return
				}
				log.Debugf("base64 decoded unsigned named file %d: %s", i, unsignedNamedFile.Name)
				unsignedNamedFiles = append(unsignedNamedFiles, *unsignedNamedFile)
			}
			log.Debugf("signing %d unsigned named files", len(unsignedNamedFiles))
		} else {
			// Decode the base64 input data
			input, err = base64.StdEncoding.DecodeString(sigreq.Input)
			if err != nil {
				httpError(w, r, http.StatusBadRequest, "%v", err)
				return
			}
		}

		// returns an error if the signer is not found or if
		// the user is not allowed to use this signer
		requestedSigner, err := a.authBackend.getSignerForUser(userid, sigreq.KeyID)
		if err != nil {
			httpError(w, r, http.StatusUnauthorized, "%v", err)
			return
		}
		requestedSignerConfig := requestedSigner.Config()
		a.stats.Incr("signer.requests", []string{"keyid:" + requestedSignerConfig.ID, "user:" + userid, usedDefaultSignerTag(sigreq)}, 1.0)

		sigresps[i] = formats.SignatureResponse{
			Ref:        id(),
			Type:       requestedSignerConfig.Type,
			Mode:       requestedSignerConfig.Mode,
			SignerID:   requestedSignerConfig.ID,
			PublicKey:  requestedSignerConfig.PublicKey,
			SignedFile: base64.StdEncoding.EncodeToString(signedfile),
			X5U:        rewriteLocalX5U(r, requestedSignerConfig.ID, requestedSignerConfig.X5U),
			SignerOpts: requestedSignerConfig.SignerOpts,
		}

		// Make sure the signer implements the right interface, then sign the data
		switch r.URL.RequestURI() {
		case "/sign/hash":
			hashSigner, ok := requestedSigner.(signer.HashSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer %q does not implement hash signing", requestedSignerConfig.ID)
				return
			}
			// the input is already a hash just convert it to hex
			inputHash = fmt.Sprintf("%X", input)

			sig, err = hashSigner.SignHash(input, sigreq.Options)
			if err != nil {
				logSigningRequestFailure(sigreq, sigresps[i], rid, userid, inputHash, inputHashes, starttime, err)
				httpError(w, r, http.StatusInternalServerError, "signing request %s failed with error: %v", sigresps[i].Ref, err)
				return
			}
			sigresps[i].Signature, err = sig.Marshal()
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "encoding failed with error: %v", err)
				return
			}
			outputHash = "unimplemented"
		case "/sign/data":
			dataSigner, ok := requestedSigner.(signer.DataSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer %q does not implement data signing", requestedSignerConfig.ID)
				return
			}
			// calculate a hash of the input to store in the signing logs
			inputHash = hashSHA256AsHex(input)

			sig, err = dataSigner.SignData(input, sigreq.Options)
			if err != nil {
				logSigningRequestFailure(sigreq, sigresps[i], rid, userid, inputHash, inputHashes, starttime, err)
				httpError(w, r, http.StatusInternalServerError, "signing request %s failed with error: %v", sigresps[i].Ref, err)
				return
			}
			sigresps[i].Signature, err = sig.Marshal()
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "encoding failed with error: %v", err)
				return
			}
			outputHash = hashSHA256AsHex([]byte(sigresps[i].Signature))
		case "/sign/file":
			fileSigner, ok := requestedSigner.(signer.FileSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer %q does not implement file signing", requestedSignerConfig.ID)
				return
			}
			// calculate a hash of the input to store in the signing logs
			inputHash = hashSHA256AsHex(input)

			signedfile, err = fileSigner.SignFile(input, sigreq.Options)
			if err != nil {
				logSigningRequestFailure(sigreq, sigresps[i], rid, userid, inputHash, inputHashes, starttime, err)
				httpError(w, r, http.StatusInternalServerError, "signing request %s failed with error: %v", sigresps[i].Ref, err)
				return
			}
			sigresps[i].SignedFile = base64.StdEncoding.EncodeToString(signedfile)
			outputHash = hashSHA256AsHex(signedfile)
		case "/sign/files":
			multiFileSigner, ok := requestedSigner.(signer.MultipleFileSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer %q does not implement multiple file signing", requestedSignerConfig.ID)
				return
			}
			// calculate a hash of the input files to log
			for _, inputFile := range unsignedNamedFiles {
				inputHashes = append(inputHashes, hashSHA256AsHex(inputFile.Bytes))
			}

			signedfiles, err = multiFileSigner.SignFiles(unsignedNamedFiles, sigreq.Options)
			if err != nil {
				logSigningRequestFailure(sigreq, sigresps[i], rid, userid, inputHash, inputHashes, starttime, err)
				httpError(w, r, http.StatusInternalServerError, "signing request %s failed with error: %v", sigresps[i].Ref, err)
				return
			}
			for _, signedFile := range signedfiles {
				outputHashes = append(outputHashes, hashSHA256AsHex(signedFile.Bytes))
				sigresps[i].SignedFiles = append(sigresps[i].SignedFiles, *signedFile.RESTSigningFile())
			}
		}
		log.WithFields(log.Fields{
			"rid":           rid,
			"request_uri":   r.URL.RequestURI(),
			"options":       sigreq.Options,
			"mode":          sigresps[i].Mode,
			"ref":           sigresps[i].Ref,
			"type":          sigresps[i].Type,
			"signer_id":     sigresps[i].SignerID,
			"input_hash":    inputHash,
			"input_hashes":  inputHashes,
			"output_hash":   outputHash,
			"output_hashes": outputHashes,
			"user_id":       userid,
			"t":             int32(time.Since(starttime) / time.Millisecond), //  request processing time in ms
		}).Info("signing operation succeeded")
	}
	respdata, err := json.Marshal(sigresps)
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, "signing failed with error: %v", err)
		return
	}
	if a.debug {
		fmt.Printf("signature response\n------------------\n%s\n", respdata)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(respdata)
	log.WithFields(log.Fields{
		"rid":                  rid,
		"num_signing_requests": sigReqsCount,
	}).Info("signing request completed successfully")
}

// handleLBHeartbeat returns a simple message indicating that the API is alive and well
func handleLBHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, r, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	w.Write([]byte("ohai"))
}

// handleHeartbeat checks whether backing services are enabled and
// accessible and returns 200 when they are and 502 when the
// aren't. Currently it only checks whether the HSM is accessible.
func (a *autographer) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, r, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	if a.heartbeatConf == nil {
		httpError(w, r, http.StatusInternalServerError, "Missing heartbeat config")
		return
	}
	var (
		// a map of backing service name to up or down/inaccessible status
		result         = map[string]bool{}
		status         = http.StatusOK
		requestContext = r.Context()
		rid            = getRequestID(r)
	)

	// try to fetch the private key from the HSM for the first
	// signer conf with a non-PEM private key that we saved on
	// server start
	if a.heartbeatConf.hsmSignerConf != nil {
		var (
			err                 error
			hsmSignerConf       = a.heartbeatConf.hsmSignerConf
			hsmHBTimeout        = a.heartbeatConf.HSMCheckTimeout
			checkResult         = make(chan error, 1)
			hsmHeartbeatStartTs = time.Now()
		)
		go func() {
			checkResult <- hsmSignerConf.CheckHSMConnection()
		}()
		select {
		case <-time.After(hsmHBTimeout):
			err = fmt.Errorf("checking HSM connection for signer %s private key timed out", hsmSignerConf.ID)
		case err = <-checkResult:
		}

		if err == nil {
			log.WithFields(log.Fields{
				"rid":     rid,
				"t":       int32(time.Since(hsmHeartbeatStartTs) / time.Millisecond),
				"timeout": hsmHBTimeout.String(),
			}).Info("HSM heartbeat completed successfully")
			result["hsmAccessible"] = true
			status = http.StatusOK
		} else {
			log.Errorf("error checking HSM connection for signer %s: %s", hsmSignerConf.ID, err)
			result["hsmAccessible"] = false
			status = http.StatusInternalServerError
		}
	}

	// check the database connection and return its status, but
	// don't fail the heartbeat since we only care about DB
	// connectivity on server start
	if a.db != nil {
		dbHeartbeatStartTs := time.Now()
		dbCheckCtx, dbCancel := context.WithTimeout(requestContext, a.heartbeatConf.DBCheckTimeout)
		defer dbCancel()
		err := a.db.CheckConnectionContext(dbCheckCtx)
		if err == nil {
			log.WithFields(log.Fields{
				"rid":     rid,
				"t":       int32(time.Since(dbHeartbeatStartTs) / time.Millisecond),
				"timeout": a.heartbeatConf.DBCheckTimeout.String(),
			}).Info("DB heartbeat completed successfully")
			result["dbAccessible"] = true
		} else {
			log.Errorf("error checking DB connection: %s", err)
			result["dbAccessible"] = false
		}
	}

	respdata, err := json.Marshal(result)
	if err != nil {
		log.Errorf("heartbeat failed to marshal JSON with error: %s", err)
		httpError(w, r, http.StatusInternalServerError, "error marshaling response JSON")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(respdata)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, r, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	dir, err := os.Getwd()
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, "Could not get CWD")
		return
	}
	filename := path.Clean(dir + string(os.PathSeparator) + "version.json")
	f, err := os.Open(filename)
	if err != nil {
		httpError(w, r, http.StatusNotFound, "version.json file not found")
		return
	}
	stat, err := f.Stat()
	if err != nil {
		httpError(w, r, http.StatusInternalServerError, "stat failed on version.json")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	http.ServeContent(w, r, "version.json", stat.ModTime(), f)
}

// handleGetAuthKeyIDs returns the signer (keyID param for the API)
// for the authenticated user
func (a *autographer) handleGetAuthKeyIDs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, r, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpError(w, r, http.StatusBadRequest, "failed to read request body: %s", err)
			return
		}
		if len(body) > 0 {
			httpError(w, r, http.StatusBadRequest, "endpoint received unexpected request body")
			return
		}
	}

	pathAuthID, ok := mux.Vars(r)["auth_id"]
	if !ok {
		httpError(w, r, http.StatusInternalServerError, "route is improperly configured")
		return
	}
	if !authIDFormatRegexp.MatchString(pathAuthID) {
		httpError(w, r, http.StatusBadRequest, "auth_id in URL path '%s' is invalid, it must match %s", pathAuthID, authIDFormat)
		return
	}
	_, headerAuthID, err := a.authorizeHeader(r)
	if err != nil {
		httpError(w, r, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}

	if headerAuthID != pathAuthID {
		httpError(w, r, http.StatusForbidden, "Authorized user %q cannot request keyids for user %q", headerAuthID, pathAuthID)
		return
	}

	signerIDsJSON, err := json.Marshal(a.authBackend.getSignerIDsForUser(pathAuthID))
	if err != nil {
		log.Errorf("handleGetAuthKeyIDs failed to marshal JSON with error: %s", err)
		httpError(w, r, http.StatusInternalServerError, "error marshaling response JSON")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(signerIDsJSON)
}

// usedDefaultSignerTag returns a statds tag indicating whether the default
// signer for an authorization was used.
func usedDefaultSignerTag(sigreq formats.SignatureRequest) string {
	// TODO(AUT-206): remove this when we've migrate everyone off of the default
	// keyid
	if sigreq.KeyID == "" {
		return "used_default_signer:true"
	}
	return "used_default_signer:false"
}
