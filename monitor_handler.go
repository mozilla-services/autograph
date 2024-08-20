package main

import (
	"encoding/json"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

const monitorAuthID = "monitor"

// MonitoringInputData is the data signed by the monitoring handler
var MonitoringInputData = []byte(`AUTOGRAPH MONITORING`)

func (m *monitor) handleMonitor(w http.ResponseWriter, r *http.Request) {
	rid := getRequestID(r)
	starttime := time.Now()
	userid, err := m.authorize(r, []byte(""))
	if err != nil {
		httpError(w, r, http.StatusUnauthorized, "authorization verification failed: %v", err)
		return
	}
	if userid != monitorAuthID {
		httpError(w, r, http.StatusUnauthorized, "user is not permitted to call this endpoint")
		return
	}

	// Wait until the results have been populated with an initial check
	<-m.initialized

	m.RLock()
	defer m.RUnlock()

	for _, errstr := range m.sigerrstrs {
		if errstr != "" {
			httpError(w, r, http.StatusInternalServerError, errstr)
			return
		}
	}

	if m.debug {
		log.Printf("signature response: %s", m.sigresps)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	enc := json.NewEncoder(w)
	for _, response := range m.sigresps {
		response.X5U = rewriteLocalX5U(r, response.SignerID, response.X5U)
		if err := enc.Encode(&response); err != nil {
			httpError(w, r, http.StatusInternalServerError, "encoding failed with error: %v", err)
			return
		}
	}

	log.WithFields(log.Fields{
		"rid":     rid,
		"user_id": userid,
		"t":       int32(time.Since(starttime) / time.Millisecond), //  request processing time in ms
	}).Info("monitoring operation succeeded")
}
