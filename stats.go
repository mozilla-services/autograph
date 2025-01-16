package main

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

var (
	// TODO(AUT-393): remove the statsd and prometheus counter using this name
	// once we're done testing.
	foobarTestCounterName = "foobar_test"
	foobarTestCounter     = promauto.NewCounter(prometheus.CounterOpts{
		Name: foobarTestCounterName,
		Help: "A counter used for testing how prometheus and statsd metrics differ",
	})
	promOnlyFoobarTestCounterName = promauto.NewCounter(prometheus.CounterOpts{
		Name: "prom_only_foobar_test",
		Help: "A counter used for testing how prometheus and statsd metrics differ",
	})

	signerRequestsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "signer_requests",
		Help: "A counter for how many authenticated and authorized requests are made to a given signer",
	}, []string{"keyid", "user", "used_default_signer"})

	httpResponsesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_responses_total",
		Help: "A counter for how many HTTP responses were returned labeled by by the HTTP handler's name, whether the response was from a signer API call (0 for false, 1 if true), and the HTTP response status code group (2xx, 3xx, etc)",
	}, []string{"handler", "is_api", "status_group"})

	httpRequestsInflight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "http_inflight_requests",
		Help: "A gauge for how many HTTP requests are currently being processed labeled by the HTTP handler's name and whether the request is from a signer API call (0 for false, 1 if true)",
	}, []string{"handler", "is_api"})
)

func loadStatsd(conf configuration) (*statsd.Client, error) {
	statsdClient, err := statsd.New(conf.Statsd.Addr, statsd.WithNamespace(conf.Statsd.Namespace))
	if err != nil {
		return nil, fmt.Errorf("error constructing statsdClient: %w", err)
	}

	return statsdClient, nil
}

func (a *autographer) addStats(conf configuration) error {
	if conf.Statsd.Addr == "" {
		// a.stats is set to a safe value in newAutographer, so we leave it
		// alone and return.
		log.Infof("Statsd left disabled as no `statsd.addr` was provided in config")
		return nil
	}

	stats, err := loadStatsd(conf)
	if err != nil {
		return err
	}
	a.stats = stats
	log.Infof("Statsd enabled at %s with namespace %s", conf.Statsd.Addr, conf.Statsd.Namespace)
	return nil
}

// newStatsdWriter returns a new http.ResponseWriter that sends HTTP response
// statuses as metrics to statsd. The metric emitted is the given metricPrefix
// suffixed with ".response.status.<status code>". The whole metric for
// "myhandler" will be something like "myhandler.response.status.200". The
// returned http.ResponseWriter doesn't support the http.Flusher or
// http.Hijacker type.
func newStatsdWriter(w http.ResponseWriter, metricPrefix string, stats statsd.ClientInterface) *statsdWriter {
	return &statsdWriter{ResponseWriter: w, metricPrefix: metricPrefix, stats: stats, headerWritten: new(atomic.Bool)}
}

var _ http.ResponseWriter = &statsdWriter{}

type statsdWriter struct {
	http.ResponseWriter
	metricPrefix string
	stats        statsd.ClientInterface

	headerWritten *atomic.Bool
}

func (w *statsdWriter) Write(b []byte) (int, error) {
	if !w.headerWritten.Load() {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statsdWriter) WriteHeader(statusCode int) {
	if w.headerWritten.CompareAndSwap(false, true) {
		switch {
		case statusCode >= 200 && statusCode < 300:
			w.stats.Incr(fmt.Sprintf("%s.response.status.2xx", w.metricPrefix), nil, 1)
			w.stats.Incr(fmt.Sprintf("%s.response.success", w.metricPrefix), nil, 1)
		case statusCode >= 300 && statusCode < 400:
			w.stats.Incr(fmt.Sprintf("%s.response.status.3xx", w.metricPrefix), nil, 1)
		case statusCode >= 400 && statusCode < 500:
			w.stats.Incr(fmt.Sprintf("%s.response.status.4xx", w.metricPrefix), nil, 1)
			// 4xx is a success code for availability since this is
			// generally folks messing up their authentication. Still want
			// to have these on a dashboard as a double check, though.
			w.stats.Incr(fmt.Sprintf("%s.response.success", w.metricPrefix), nil, 1)
		case statusCode >= 500 && statusCode < 600:
			w.stats.Incr(fmt.Sprintf("%s.response.status.5xx", w.metricPrefix), nil, 1)
		}
		w.stats.Incr(fmt.Sprintf("%s.response.status.%d", w.metricPrefix, statusCode), nil, 1)
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// statsMiddleware is an HTTP handler for emitting a statsd metric of request
// attempts and returns an http.ResponseWriter for recording HTTP response
// status codes with newStatsdWriter. It also emits a metric for how many
// requests it has received (before attemping to process those requests) called
// "<handlerName>.request.attempts".
func statsdMiddleware(h http.HandlerFunc, handlerName string, stats statsd.ClientInterface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats.Incr(handlerName+".request.attempts", nil, 1)
		w = newStatsdWriter(w, handlerName, stats)
		h(w, r)
	}
}

// apiStatsMiddleware is a handler that emits the Prometheus metrics
// `http_responses_total“ and `http_inflight_requests_total` with the label
// `is_api` set to `1` as well as the StatsD metrics
// "agg.http.api.request.attempts" and "agg.http.api.response.status.<status
// code>" as well as statsdMiddleware metrics for the handlerName given. These
// metrics represent roll-ups of the individual http.api.* metrics. This
// function only needs to exist for as long as we're running in AWS. It's
// required because our combination of Grafana 0.9 and InfluxDB 1.11 doesn't
// allow us to sum over the individual http.api.* API request metrics. So, we do
// the aggregation ourselves. The "agg" is short for "aggregated". The
// handlerName provided should still include "http.api".
func apiStatsMiddleware(h http.HandlerFunc, handlerName string, stats statsd.ClientInterface) http.HandlerFunc {
	totalRequests := httpResponsesTotal.MustCurryWith(prometheus.Labels{"handler": handlerName, "is_api": "1"})
	totalInflight := httpRequestsInflight.With(prometheus.Labels{"handler": handlerName, "is_api": "1"})
	handlerFunc := promMiddleware(h, totalRequests, totalInflight)
	handlerFunc = statsdMiddleware(handlerFunc, "http.api."+handlerName, stats)
	return statsdMiddleware(handlerFunc, "agg.http.api", stats)
}

// apiStatsMiddleware is a handler that emits the Prometheus metrics
// `http_responses_total“ and `http_inflight_requests_total` with the label
// `is_api` set to `0` as well as the StatsD metrics
// "agg.http.nonapi.request.attempts" and
// "agg.http.nonapi.response.status.<status code>" as well as statsdMiddleware
// metrics for the handlerName given.
func nonAPIstatsMiddleware(h http.HandlerFunc, handlerName string, stats statsd.ClientInterface) http.HandlerFunc {
	totalRequests := httpResponsesTotal.MustCurryWith(prometheus.Labels{"handler": handlerName, "is_api": "0"})
	totalInflight := httpRequestsInflight.With(prometheus.Labels{"handler": handlerName, "is_api": "0"})
	handlerFunc := promMiddleware(h, totalRequests, totalInflight)
	handlerFunc = statsdMiddleware(handlerFunc, "http.nonapi."+handlerName, stats)
	return statsdMiddleware(handlerFunc, "agg.http.nonapi", stats)
}

func newPromWriter(w http.ResponseWriter, totalRequests *prometheus.CounterVec) *promWriter {
	return &promWriter{ResponseWriter: w, totalRequests: totalRequests, headerWritten: new(atomic.Bool)}
}

type promWriter struct {
	http.ResponseWriter
	totalRequests *prometheus.CounterVec
	headerWritten *atomic.Bool
}

func (w *promWriter) Write(b []byte) (int, error) {
	if !w.headerWritten.Load() {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *promWriter) WriteHeader(statusCode int) {
	if w.headerWritten.CompareAndSwap(false, true) {
		statusGroup := "unknown"
		switch {
		case statusCode >= 200 && statusCode < 300:
			statusGroup = "2xx"
		case statusCode >= 300 && statusCode < 400:
			statusGroup = "3xx"
		case statusCode >= 400 && statusCode < 500:
			statusGroup = "4xx"
		case statusCode >= 500 && statusCode < 600:
			statusGroup = "5xx"
		}
		w.totalRequests.With(prometheus.Labels{"status_group": statusGroup}).Inc()
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func promMiddleware(h http.HandlerFunc, totalRequests *prometheus.CounterVec, totalInflight prometheus.Gauge) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		totalInflight.Inc()
		defer totalInflight.Dec()
		w = newPromWriter(w, totalRequests)
		h(w, r)
	}
}
