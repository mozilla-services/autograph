package main

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const statsNamespace = "autograph"

var (
	requestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "requests",
		Namespace: statsNamespace,
		Help:      "A counter for how many requests are made to a given handler",
	}, []string{"handler"})

	signerRequestsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "signer_requests",
		Namespace: statsNamespace,
		Help:      "A counter for how many authenticated and authorized requests are made to a given signer",
	}, []string{"keyid", "user", "used_default_signer"})

	signerRequestsTiming = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name:      "signer_request_timing",
		Namespace: statsNamespace,
		Help:      "A summary vector for request timing",
	}, []string{"step"})

	responseStatusCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "response_status",
		Namespace: statsNamespace,
		Help:      "A counter for response status codes for a given handler",
	}, []string{"handler", "statusCode"})

	responseSuccessCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "response_success",
		Namespace: statsNamespace,
		Help:      "A counter for succesful vs failed response status codes",
	}, []string{"handler", "status"})
)

// newStatsWriter returns a new http.ResponseWriter that sends HTTP response
// statuses as metrics to prometheus. The metric emitted is the given metric
// labeled with the status code and handler name. The returned
// http.ResponseWriter doesn't support the http.Flusher or http.Hijacker type.
func newStatsWriter(w http.ResponseWriter, handlerName string) *statsWriter {
	return &statsWriter{ResponseWriter: w, handlerName: handlerName, headerWritten: new(atomic.Bool)}
}

var _ http.ResponseWriter = &statsWriter{}

type statsWriter struct {
	http.ResponseWriter
	handlerName   string
	headerWritten *atomic.Bool
}

func (w *statsWriter) Write(b []byte) (int, error) {
	if !w.headerWritten.Load() {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statsWriter) WriteHeader(statusCode int) {
	if w.headerWritten.CompareAndSwap(false, true) {
		responseStatusCounter.With(prometheus.Labels{
			"handler":    w.handlerName,
			"statusCode": fmt.Sprintf("%d", statusCode),
		}).Inc()

		if statusCode >= 200 && statusCode < 300 {
			responseSuccessCounter.With(prometheus.Labels{
				"handler": w.handlerName,
				"status":  "success",
			}).Inc()
		} else if statusCode >= 400 && statusCode < 500 {
			responseSuccessCounter.With(prometheus.Labels{
				"handler": w.handlerName,
				"status":  "client_failure",
			}).Inc()
		} else {
			responseSuccessCounter.With(prometheus.Labels{
				"handler": w.handlerName,
				"status":  "failure",
			}).Inc()
		}

		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// statsMiddleware is an HTTP handler for emitting a metric of request
// attempts and returns an http.ResponseWriter for recording HTTP response
// status codes with newStatsWriter. It also emits a metric for how many
// requests it has received (before attemping to process those requests) called
// "<handlerName>.request.attempts".
func statsMiddleware(h http.HandlerFunc, handlerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestCounter.With(prometheus.Labels{
			"handler": handlerName,
		}).Inc()
		w = newStatsWriter(w, handlerName)
		h(w, r)
	}
}

// apiStatsMiddleware is a handler that emits the metrics
// "agg.http.api.request.attempts" and "agg.http.api.response.status.<status
// code>" as well as statsMiddleware metrics for the handlerName given. These
// metrics represent roll-ups of the individual http.api.* metrics. This
// function only needs to exist for as long as we're running in AWS. It's
// required because our combination of Grafana 0.9 and InfluxDB 1.11 doesn't
// allow us to sum over the individual http.api.* API request metrics. So, we do
// the aggregation ourselves. The "agg" is short for "aggregated". The
// handlerName provided should still include "http.api".
func apiStatsMiddleware(h http.HandlerFunc, handlerName string) http.HandlerFunc {
	handlerFunc := statsMiddleware(h, handlerName)
	return statsMiddleware(handlerFunc, "agg.http.api")
}
