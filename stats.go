package main

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/DataDog/datadog-go/statsd"

	log "github.com/sirupsen/logrus"
)

func loadStatsd(conf configuration) (*statsd.Client, error) {
	statsdClient, err := statsd.NewBuffered(conf.Statsd.Addr, conf.Statsd.Buflen)
	if err != nil {
		return nil, fmt.Errorf("error constructing statsdClient: %w", err)
	}
	statsdClient.Namespace = conf.Statsd.Namespace

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
		w.stats.Incr(fmt.Sprintf("%s.response.status.%d", w.metricPrefix, statusCode), nil, 1)
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// statsMiddleware is an HTTP handler for emitting a statsd metric of request
// attempts and returns an http.ResponseWriter for recording HTTP response
// status codes with newStatsdWriter. It also emits a metric for how many
// requests it has received (before attemping to process those requests) called
// "<handlerName>.request.attempts".
func statsMiddleware(h http.HandlerFunc, handlerName string, stats statsd.ClientInterface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats.Incr(handlerName+".request.attempts", nil, 1)
		w = newStatsdWriter(w, handlerName, stats)
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
func apiStatsMiddleware(h http.HandlerFunc, handlerName string, stats statsd.ClientInterface) http.HandlerFunc {
	handlerFunc := statsMiddleware(h, handlerName, stats)
	return statsMiddleware(handlerFunc, "agg.http.api", stats)
}
