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

	for _, errstr := range m.sigerrstrs {
		if errstr != "" {
			m.RUnlock()
			httpError(w, r, http.StatusInternalServerError, errstr)
			return
		}
	}

	respdata, err := json.Marshal(m.sigresps)

	m.RUnlock()

	if err != nil {
		httpError(w, r, http.StatusInternalServerError, "signing failed with error: %v", err)
		return
	}
	if m.debug {
		log.Printf("signature response: %s", respdata)
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(respdata)
	log.WithFields(log.Fields{
		"rid":     rid,
		"user_id": userid,
		"t":       int32(time.Since(starttime) / time.Millisecond), //  request processing time in ms
	}).Info("monitoring operation succeeded")
}
