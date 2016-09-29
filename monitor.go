package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func (a *autographer) addMonitoring(monitoring authorization) {
	if monitoring.Key == "" {
		return
	}
	if _, ok := a.auths["monitor"]; ok {
		panic("user 'monitor' is reserved for monitoring, duplication is not permitted")
	}
	a.auths["monitor"] = monitoring
}

func (a *autographer) handleMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		httpError(w, http.StatusMethodNotAllowed, "%s method not allowed; endpoint accepts GET only", r.Method)
		return
	}
	userid, authorized, err := a.authorize(r, []byte(""))
	if err != nil || !authorized {
		httpError(w, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	if userid != "monitor" {
		httpError(w, http.StatusUnauthorized, "user is not permitted to call this endpoint")
		return
	}
	sigresps := make([]signatureresponse, len(a.signers)*2)
	for i, signer := range a.signers {
		for j, template := range []string{"", "content-signature"} {
			var (
				hash                       []byte
				alg, encodedcs, encodedsig string
			)
			sigreq := signaturerequest{
				// base64 of the string 'AUTOGRAPH MONITORING'
				Input:    "QVVUT0dSQVBIIE1PTklUT1JJTkc=",
				Template: template,
			}
			alg, hash, err = templateAndHash(sigreq, signer.ecdsaPrivKey.Curve.Params().Name)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "%v", err)
				return
			}
			ecdsaSig, err := signer.sign(hash)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
				return
			}
			encodedsig, err = encode(ecdsaSig, signer.siglen, sigreq.Encoding)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "encoding failed with error: %v", err)
				return
			}
			if sigreq.Template == "content-signature" {
				encodedcs, err = signer.ContentSignature(ecdsaSig)
				if err != nil {
					httpError(w, http.StatusInternalServerError, "failed to retrieve content-signature: %v", err)
					return
				}
			}
			sigresps[i*2+j] = signatureresponse{
				Ref:              id(),
				SignerID:         signer.ID,
				X5U:              signer.X5U,
				PublicKey:        signer.PublicKey,
				Hash:             alg,
				Encoding:         sigreq.Encoding,
				Signature:        encodedsig,
				ContentSignature: encodedcs,
			}
		}
	}
	respdata, err := json.Marshal(sigresps)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "signing failed with error: %v", err)
		return
	}
	if a.debug {
		log.Printf("signature response: %s", respdata)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(respdata)
	log.Printf("monitoring operation succeeded")
}
