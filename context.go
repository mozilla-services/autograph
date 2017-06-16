package main

import (
	"context"
	"net/http"
	"time"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "go.mozilla.org/autograph context value " + k.name }

var (
	// ctxReqID is the string identifier of a request ID in a context
	contextKeyRequestID = contextKey{name: "reqID"}

	// ctxReqStartTime is the string identifier of a timestamp that
	// marks the beginning of processing of a request in a context
	contextKeyRequestStartTime = contextKey{name: "reqStartTime"}
)

// addToContext add the given key value pair to the given request's context
func addToContext(r *http.Request, key contextKey, value interface{}) *http.Request {
	ctx := r.Context()
	return r.WithContext(context.WithValue(ctx, key, value))
}

// getRequestID retrieves an ID from the request context, or returns "-" is none is found
func getRequestID(r *http.Request) string {
	val, ok := r.Context().Value(contextKeyRequestID).(string)
	if ok {
		return val
	}
	return "-"
}

// getRequestStartTime retrieves a start time from the request context,
// or returns the current time is none is found
func getRequestStartTime(r *http.Request) time.Time {
	val, ok := r.Context().Value(contextKeyRequestStartTime).(time.Time)
	if ok {
		return val
	}
	return time.Now()
}
