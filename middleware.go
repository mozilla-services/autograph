package main

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Middleware wraps an http.Handler with additional functionality
type Middleware func(http.Handler) http.Handler

func setResponseHeaders() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Security-Policy", "default-src 'none'; object-src 'none';")
			w.Header().Add("X-Frame-Options", "SAMEORIGIN")
			w.Header().Add("X-Content-Type-Options", "nosniff")
			w.Header().Add("Strict-Transport-Security", "max-age=31536000;")
			h.ServeHTTP(w, r)
		})
	}
}

// setRequestID is a middleware the generates a random ID for each request processed
// by the HTTP server. The request ID is added to the request context and used to
// track various information and correlate logs.
func setRequestID() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// NewV7 is used instead of New because the latter will panic
			// if can't generate a UUID. It's preferably for us to have
			// worse request ids than panic.
			uuid, err := uuid.NewV7()
			var rid string
			if err != nil {
				rid = "-"
			} else {
				rid = uuid.String()
			}

			h.ServeHTTP(w, addToContext(r, contextKeyRequestID, rid))
		})
	}
}

// setRequestStartTime is a middleware that stores a timestamp of the time a request entering
// the middleware, to calculate processing time later on
func setRequestStartTime() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, addToContext(r, contextKeyRequestStartTime, time.Now()))
		})
	}
}

// Run the request through all middlewares
func handleMiddlewares(h http.Handler, adapters ...Middleware) http.Handler {
	// To make the middleware run in the order in which they are specified,
	// we reverse through them in the Middleware function, rather than just
	// ranging over them
	for i := len(adapters) - 1; i >= 0; i-- {
		h = adapters[i](h)
	}
	return h
}
