package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/mock/gomock"
)

func TestStatsResponseWriterWritesResponseMetricOnce(t *testing.T) {
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

	// With Gauge Metric
	if testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "client_failure")) != float64(1) {
		t.Fatalf("Expected responseSuccessGauge to be 1, got %f", testutil.ToFloat64(responseSuccessGauge.WithLabelValues("myhandler", "client_failure")))
	}

	if testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "400")) != float64(1) {
		t.Fatalf("Expected responseStatusGauge to be 1, got %f", testutil.ToFloat64(responseStatusGauge.WithLabelValues("myhandler", "400")))
	}
}

func TestStatsResponseWriterWritesToHeaderOnWrite(t *testing.T) {
	responseSuccessGauge.Reset()
	responseStatusGauge.Reset()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	recorder := httptest.NewRecorder()
	statsWriter := newStatsWriter(recorder, "myhandler")
	statsWriter.Write([]byte("hello"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, recorder.Code)
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	recorder := httptest.NewRecorder()
	inner := newStatsWriter(recorder, "inner")
	wrapper := newStatsWriter(inner, "wrapper")

	wrapper.WriteHeader(http.StatusInternalServerError)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
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
