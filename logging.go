package main

import (
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph")
}

// logRequest is a middleware that writes details about each HTTP request processed
// but the various handlers. It is executed last to capture signing logs as well.
func logRequest() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			// attempt to retrieve a signing registry entry for this request
			// from the global sr.entry map, using mutexes
			rid := getRequestID(r)
			// calculate the processing time
			t1 := getRequestStartTime(r)
			procTs := time.Now().Sub(t1)
			log.WithFields(log.Fields{
				"remoteAddress":      r.RemoteAddr,
				"remoteAddressChain": "[" + r.Header.Get("X-Forwarded-For") + "]",
				"method":             r.Method,
				"proto":              r.Proto,
				"url":                r.URL.String(),
				"ua":                 r.UserAgent(),
				"rid":                rid,
				"t":                  procTs / time.Millisecond,
			}).Info("request")
		})
	}
}
