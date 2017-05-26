package main

import (
	"math/rand"
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
			t1 := r.Context().Value(ctxReqStartTime).(time.Time)
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

// ctxReqID is the string identifier of a request ID in a context
const ctxReqID = "reqID"

// ctxReqStartTime is the string identifier of a timestamp that
// marks the beginning of processing of a request in a context
const ctxReqStartTime = "reqStartTime"

// addRequestID is a middleware the generates a random ID for each request processed
// by the HTTP server. The request ID is added to the request context and used to
// track various information and correlate logs.
func addRequestID() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid := make([]rune, 16)
			letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
			for i := range rid {
				rid[i] = letters[rand.Intn(len(letters))]
			}

			h.ServeHTTP(w, addtoContext(r, ctxReqID, string(rid)))
		})
	}
}

// addRequestStartTime is a middleware that stores a timestamp of the time a request entered
// the middleware, to calculate processing time later on
func addRequestStartTime() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, addtoContext(r, ctxReqStartTime, time.Now()))
		})
	}
}

func getRequestID(r *http.Request) string {
	val := r.Context().Value(ctxReqID)
	if val != nil {
		return val.(string)
	}
	return "-"
}
