package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/mock/gomock"
)

func TestStatsResponseWriterWritesResponseMetricOnce(t *testing.T) {
	responseSuccessCounter.Reset()
	responseStatusCounter.Reset()
	responseSuccessGauge.Reset()
	responseStatusGauge.Reset()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	recorder := httptest.NewRecorder()
	statsWriter := newStatsWriter(recorder, "myhandler")
	statsWriter.WriteHeader(http.StatusBadRequest)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status code %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	statsWriter.WriteHeader(http.StatusCreated)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tried to write to the headers again: Expected status code %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	if testutil.ToFloat64(responseSuccessCounter.WithLabelValues("myhandler", "client_failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessCounter to be 1, got %f", testutil.ToFloat64(responseSuccessCounter.WithLabelValues("myhandler", "client_failure")))
	}

	if testutil.ToFloat64(responseStatusCounter.WithLabelValues("myhandler", "400")) != float64(1) {
		t.Fatalf("Expected responseStatusCounter to be 1, got %f", testutil.ToFloat64(responseStatusCounter.WithLabelValues("myhandler", "400")))
	}

	// With Gauge Metric
	if testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "client_failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessGauge to be 1, got %f", testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "client_failure")))
	}

	if testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "400")) != float64(1) {
		t.Fatalf("Expected responseStatusGauge to be 1, got %f", testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "400")))
	}
}

func TestStatsResponseWriterWritesToHeaderOnWrite(t *testing.T) {
	responseSuccessCounter.Reset()
	responseStatusCounter.Reset()
	responseSuccessGauge.Reset()
	responseStatusGauge.Reset()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	recorder := httptest.NewRecorder()
	statsWriter := newStatsWriter(recorder, "myhandler")
	_, err := statsWriter.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error writing to statsWriter: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, recorder.Code)
	}

	if testutil.ToFloat64(responseSuccessCounter.WithLabelValues("myhandler", "success")) != float64(1) {
		t.Fatalf("Expected responseSuccessCounter to be 1, got %f", testutil.ToFloat64(responseSuccessCounter.WithLabelValues("myhandler", "success")))
	}

	if testutil.ToFloat64(responseStatusCounter.WithLabelValues("myhandler", "200")) != float64(1) {
		t.Fatalf("Expected responseStatusCounter to be 1, got %f", testutil.ToFloat64(responseStatusCounter.WithLabelValues("myhandler", "200")))
	}

	// With Gauge Metric
	if testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "success")) != float64(1) {
		t.Fatalf("Expected responseSuccessGauge to be 1, got %f", testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "success")))
	}

	if testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "200")) != float64(1) {
		t.Fatalf("Expected responseStatusGauge to be 1, got %f", testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "200")))
	}
}

func TestWrappingStatsResponseWriteWritesAllMetrics(t *testing.T) {
	responseSuccessCounter.Reset()
	responseStatusCounter.Reset()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	recorder := httptest.NewRecorder()
	inner := newStatsWriter(recorder, "inner")
	wrapper := newStatsWriter(inner, "wrapper")

	wrapper.WriteHeader(http.StatusInternalServerError)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
	}

	if testutil.ToFloat64(responseSuccessCounter.WithLabelValues("wrapper", "failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessCounter to be 1, got %f", testutil.ToFloat64(responseSuccessCounter.WithLabelValues("myhandler", "failure")))
	}

	if testutil.ToFloat64(responseStatusCounter.WithLabelValues("wrapper", "500")) != float64(1) {
		t.Fatalf("Expected responseStatusCounter to be 1, got %f", testutil.ToFloat64(responseStatusCounter.WithLabelValues("myhandler", "500")))
	}

	if testutil.ToFloat64(responseSuccessCounter.WithLabelValues("inner", "failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessCounter to be 1, got %f", testutil.ToFloat64(responseSuccessCounter.WithLabelValues("myhandler", "failure")))
	}

	// With Gauge Metric
	if testutil.ToFloat64(responseStatusGauge.WithLabelValues("inner", "500")) != float64(1) {
		t.Fatalf("Expected responseStatusGauge to be 1, got %f", testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "500")))
	}

	if testutil.ToFloat64(responseSuccessGauge.WithLabelValues("wrapper", "failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessGauge to be 1, got %f", testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "failure")))
	}

	if testutil.ToFloat64(responseStatusGauge.WithLabelValues("wrapper", "500")) != float64(1) {
		t.Fatalf("Expected responseStatusGauge to be 1, got %f", testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "500")))
	}

	if testutil.ToFloat64(responseSuccessGauge.WithLabelValues("inner", "failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessGauge to be 1, got %f", testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "failure")))
	}

	if testutil.ToFloat64(responseStatusGauge.WithLabelValues("inner", "500")) != float64(1) {
		t.Fatalf("Expected responseStatusGauge to be 1, got %f", testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "500")))
	}
}

func TestStatsMiddleware(t *testing.T) {
	requestCounter.Reset()
	requestGauge.Reset()
	apiResponseTiming.Reset()
	// Create a dummy handler that writes a response
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := statsMiddleware(handler, "testHandler")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	// Call the middleware
	wrapped.ServeHTTP(rr, req)

	// Check metrics
	if count := testutil.ToFloat64(requestCounter.WithLabelValues("testHandler")); count != 1 {
		t.Errorf("expected requestCounter to be 1, got %f", count)
	}
	if gauge := testutil.ToFloat64(requestGauge.WithLabelValues("testHandler")); gauge != 1 {
		t.Errorf("expected requestGauge to be 1, got %f", gauge)
	}
	// Summary will have non-zero values, so just check >0
	count := testutil.CollectAndCount(apiResponseTiming)
	if count == 0 {
		t.Errorf("expected `apiResponseTiming` to have recorded a value")
	}
}
