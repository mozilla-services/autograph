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
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/mozilla-services/autograph/formats"
	"github.com/mozilla-services/autograph/signer"
	log "github.com/sirupsen/logrus"
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

// handleSignature endpoint accepts a list of signature requests in a HAWK authenticated POST request
// and calls the signers to generate signature responses.
func (a *autographer) handleSignature(w http.ResponseWriter, r *http.Request) {
	rid := getRequestID(r)
	starttime := getRequestStartTime(r)
	auth, userid, err := a.authorizeHeader(r)
	if err != nil {
		if a.stats != nil {
			sendStatsErr := a.stats.Timing("hawk.authorize_header_failed", time.Since(starttime), nil, 1.0)
			if sendStatsErr != nil {
				log.Warnf("Error sending hawk.authorize_header_failed: %s", sendStatsErr)
			}
		}
		httpError(w, r, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
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
	if a.stats != nil {
		sendStatsErr := a.stats.Timing("authorize_finished", time.Since(starttime), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending authorize_finished: %s", sendStatsErr)
		}
	}
	if err != nil {
		httpError(w, r, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	var sigreqs []formats.SignatureRequest
	err = json.Unmarshal(body, &sigreqs)
	if a.stats != nil {
		sendStatsErr := a.stats.Timing("body_unmarshaled", time.Since(starttime), nil, 1.0)
		if sendStatsErr != nil {
			log.Warnf("Error sending body_unmarshaled: %s", sendStatsErr)
		}
	}
	if err != nil {
		httpError(w, r, http.StatusBadRequest, "failed to parse request body: %v", err)
		return
	}
	for i, sigreq := range sigreqs {
		if sigreq.Input == "" {
			httpError(w, r, http.StatusBadRequest, fmt.Sprintf("missing input in signature request %d", i))
		}
	}
	if a.debug {
		fmt.Printf("signature request\n-----------------\n%s\n", body)
	}
	sigresps := make([]formats.SignatureResponse, len(sigreqs))
	// Each signature requested in the http request body is processed individually.
	// For each, a signer is looked up, and used to compute a raw signature
	// the signature is then encoded appropriately, and added to the response slice
	for i, sigreq := range sigreqs {
		var (
			input                 []byte
			sig                   signer.Signature
			signedfile            []byte
			inputHash, outputHash string
		)

		// Decode the base64 input data
		input, err = base64.StdEncoding.DecodeString(sigreq.Input)
		if err != nil {
			httpError(w, r, http.StatusBadRequest, "%v", err)
			return
		}

		// returns an error if the signer is not found or if
		// the user is not allowed to use this signer
		requestedSigner, err := a.authBackend.getSignerForUser(userid, sigreq.KeyID)
		if err != nil {
			httpError(w, r, http.StatusUnauthorized, "%v", err)
			return
		}
		requestedSignerConfig := requestedSigner.Config()
		sigresps[i] = formats.SignatureResponse{
			Ref:        id(),
			Type:       requestedSignerConfig.Type,
			Mode:       requestedSignerConfig.Mode,
			SignerID:   requestedSignerConfig.ID,
			PublicKey:  requestedSignerConfig.PublicKey,
			SignedFile: base64.StdEncoding.EncodeToString(signedfile),
			X5U:        requestedSignerConfig.X5U,
			SignerOpts: requestedSignerConfig.SignerOpts,
		}
		// Make sure the signer implements the right interface, then sign the data
		switch r.URL.RequestURI() {
		case "/sign/hash":
			hashSigner, ok := requestedSigner.(signer.HashSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer does not implement hash signing")
				return
			}
			sig, err = hashSigner.SignHash(input, sigreq.Options)
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "signing failed with error: %v", err)
				return
			}
			sigresps[i].Signature, err = sig.(signer.Signature).Marshal()
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "encoding failed with error: %v", err)
				return
			}
			// the input is already a hash just convert it to hex
			inputHash = fmt.Sprintf("%X", input)
			outputHash = "unimplemented"
		case "/sign/data":
			dataSigner, ok := requestedSigner.(signer.DataSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer does not implement data signing")
				return
			}
			sig, err = dataSigner.SignData(input, sigreq.Options)
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "signing failed with error: %v", err)
				return
			}
			sigresps[i].Signature, err = sig.(signer.Signature).Marshal()
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "encoding failed with error: %v", err)
				return
			}
			// calculate a hash of the input to store in the signing logs
			inputHash = hashSHA256AsHex(input)
			outputHash = hashSHA256AsHex([]byte(sigresps[i].Signature))
		case "/sign/file":
			fileSigner, ok := requestedSigner.(signer.FileSigner)
			if !ok {
				httpError(w, r, http.StatusBadRequest, "requested signer does not implement file signing")
				return
			}
			signedfile, err = fileSigner.SignFile(input, sigreq.Options)
			if err != nil {
				httpError(w, r, http.StatusInternalServerError, "signing failed with error: %v", err)
				return
			}
			sigresps[i].SignedFile = base64.StdEncoding.EncodeToString(signedfile)
			// calculate a hash of the input to store in the signing logs
			inputHash = hashSHA256AsHex(input)
			outputHash = hashSHA256AsHex(signedfile)
		}
		log.WithFields(log.Fields{
			"rid":         rid,
			"options":     sigreq.Options,
			"mode":        sigresps[i].Mode,
			"ref":         sigresps[i].Ref,
			"type":        sigresps[i].Type,
			"signer_id":   sigresps[i].SignerID,
			"input_hash":  inputHash,
			"output_hash": outputHash,
			"user_id":     userid,
			"t":           int32(time.Since(starttime) / time.Millisecond), //  request processing time in ms
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
	log.WithFields(log.Fields{"rid": rid}).Info("signing request completed successfully")
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
			err = fmt.Errorf("Checking HSM connection for signer %s private key timed out", hsmSignerConf.ID)
		case err = <-checkResult:
		}

		if err == nil {
			log.WithFields(log.Fields{
				"rid":     rid,
				"t":       int32(time.Since(hsmHeartbeatStartTs) / time.Millisecond),
				"timeout": fmt.Sprintf("%s", hsmHBTimeout),
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
				"timeout": fmt.Sprintf("%s", a.heartbeatConf.DBCheckTimeout),
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
