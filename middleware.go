package main

import (
	"math/rand"
	"net/http"
	"time"
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
			rid := make([]rune, 16)
			letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
			for i := range rid {
				rid[i] = letters[rand.Intn(len(letters))]
			}

			h.ServeHTTP(w, addToContext(r, contextKeyRequestID, string(rid)))
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

//  Run the request through all middlewares
func handleMiddlewares(h http.Handler, adapters ...Middleware) http.Handler {
	// To make the middleware run in the order in which they are specified,
	// we reverse through them in the Middleware function, rather than just
	// ranging over them
	for i := len(adapters) - 1; i >= 0; i-- {
		h = adapters[i](h)
	}
	return h
}
