package main

import (
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"

	log "github.com/Sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

// sr is a global variable that holds a signing log
var sr signingRegistry

// signingRegistry is a simple structure used to pass details about
// signed data from the request handler to the logging middleware
type signingRegistry struct {
	entry map[string]signingLog
	sync.Mutex
}

// signingLog contains log details
type signingLog struct {
	log    []signatureresponse
	userid string
}

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph")
	// make a map that holds signing logs
	sr.entry = make(map[string]signingLog)
}

// logRequest is a middleware that writes details about each HTTP request processed
// but the various handlers. It is executed last to capture signing logs as well.
func logRequest() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
			// attempt to retrieve a signing registry entry for this request
			// from the global sr.entry map, using mutexes
			var sl signingLog
			rid := getRequestID(r)
			sr.Lock()
			defer sr.Unlock()
			if _, ok := sr.entry[rid]; ok {
				sl = sr.entry[rid]
				delete(sr.entry, rid)
			}
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
				"user":               sl.userid,
				"signing_log":        sl.log,
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

// buildSigningLog takes a slice of signature responses and creates a slice of signing log from it,
// which is just signature responses with the public key and signature bits removed. It puts the
// log into a signinglog.log map for the logging middleware to later capture it.
func buildSigningLog(userid string, origsigresps []signatureresponse, r *http.Request) (sigresps []signatureresponse, err error) {
	sigresps = origsigresps
	logsigresp := make([]signatureresponse, len(sigresps))
	for i := range sigresps {
		logsigresp[i] = sigresps[i]
		logsigresp[i].Signature = ""
		logsigresp[i].PublicKey = ""
	}
	var sl signingLog
	sl.log = logsigresp
	sl.userid = userid
	// take a lock to check if an entry with this rid already exists
	sr.Lock()
	defer sr.Unlock()
	rid := getRequestID(r)
	if _, ok := sr.entry[rid]; ok {
		return sigresps, errors.Errorf("a conflicting signing log entry with rid '%s' already exists", rid)
	}
	sr.entry[rid] = sl

	// do one last pass on the sigresps slice to remove the inputhash
	// values that are no longer needed and shouldn't be returned to clients
	for i := range sigresps {
		sigresps[i].InputHash = ""
	}
	return
}

func getRequestID(r *http.Request) string {
	val := r.Context().Value(ctxReqID)
	if val != nil {
		return val.(string)
	}
	return "-"
}
