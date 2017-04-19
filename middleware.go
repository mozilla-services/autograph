package main

import (
	"context"
	"net/http"
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

// addToContext add the given key value pair to the given request's context
func addtoContext(r *http.Request, key string, value interface{}) *http.Request {
	ctx := r.Context()
	return r.WithContext(context.WithValue(ctx, key, value))
}
