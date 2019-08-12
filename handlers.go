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

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/autograph/formats"
	"go.mozilla.org/autograph/signer"
)

// HeartbeatConfig configures the heartbeat handler. It sets timeouts
// for each backing service to check.
//
// `hsmHeartbeatSignerConf` is determined added on boot in initHSM
type HeartbeatConfig struct {
	HSMCheckTimeout time.Duration
	DBCheckTimeout  time.Duration

	// hsmSignerConf is the signer conf to use to check
	// HSM connectivity (set to the first signer with an HSM label
	// in initHSM) when it is non-nil
	hsmSignerConf *signer.Configuration
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
			input      []byte
			sig        signer.Signature
			signedfile []byte
			hashlog    string
		)

		// Decode the base64 input data
		input, err = base64.StdEncoding.DecodeString(sigreq.Input)
		if err != nil {
			httpError(w, r, http.StatusBadRequest, "%v", err)
			return
		}

		// Find the ID of the requested signer
		// Return an error if the signer is not found or if the user is not allowed
		// to use this signer
		signerID, err := a.getSignerID(userid, sigreq.KeyID)
		if err != nil || signerID < 0 {
			httpError(w, r, http.StatusUnauthorized, "%v", err)
			return
		}
		sigresps[i] = formats.SignatureResponse{
			Ref:        id(),
			Type:       a.signers[signerID].Config().Type,
			Mode:       a.signers[signerID].Config().Mode,
			SignerID:   a.signers[signerID].Config().ID,
			PublicKey:  a.signers[signerID].Config().PublicKey,
			SignedFile: base64.StdEncoding.EncodeToString(signedfile),
			X5U:        a.signers[signerID].Config().X5U,
			SignerOpts: a.signers[signerID].Config().SignerOpts,
		}
		// Make sure the signer implements the right interface, then sign the data
		switch r.URL.RequestURI() {
		case "/sign/hash":
			hashSigner, ok := a.signers[signerID].(signer.HashSigner)
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
			// convert the input hash to hexadecimal for logging
			hashlog = fmt.Sprintf("%X", input)

		case "/sign/data":
			dataSigner, ok := a.signers[signerID].(signer.DataSigner)
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
			md := sha256.New()
			md.Write(input)
			hashlog = fmt.Sprintf("%X", md.Sum(nil))

		case "/sign/file":
			fileSigner, ok := a.signers[signerID].(signer.FileSigner)
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
			md := sha256.New()
			md.Write(input)
			hashlog = fmt.Sprintf("%X", md.Sum(nil))
		}
		log.WithFields(log.Fields{
			"rid":        rid,
			"options":    sigreq.Options,
			"mode":       sigresps[i].Mode,
			"ref":        sigresps[i].Ref,
			"type":       sigresps[i].Type,
			"signer_id":  sigresps[i].SignerID,
			"input_hash": hashlog,
			"user_id":    userid,
			"t":          int32(time.Since(starttime) / time.Millisecond), //  request processing time in ms
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
	)

	// try to fetch the private key from the HSM for the first
	// signer conf with a non-PEM private key that we saved on
	// server start
	if a.heartbeatConf.hsmSignerConf != nil {
		var (
			err         error
			conf        = a.heartbeatConf.hsmSignerConf
			checkResult = make(chan error, 1)
		)
		go func() {
			checkResult <- conf.CheckHSMConnection()
		}()
		select {
		case <-time.After(a.heartbeatConf.HSMCheckTimeout):
			err = fmt.Errorf("Checking HSM connection for signer %s private key timed out", conf.ID)
		case err = <-checkResult:
		}

		if err == nil {
			result["hsmAccessible"] = true
			status = http.StatusOK
		} else {
			log.Errorf("error checking HSM connection for signer %s: %s", conf.ID, err)
			result["hsmAccessible"] = false
			status = http.StatusInternalServerError
		}
	}

	// check the database connection and return its status, but
	// don't fail the heartbeat since we only care about DB
	// connectivity on server start
	if a.db != nil {
		dbCheckCtx, dbCancel := context.WithTimeout(requestContext, a.heartbeatConf.DBCheckTimeout)
		defer dbCancel()
		err := a.db.CheckConnectionContext(dbCheckCtx)
		if err == nil {
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
