package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	// We generated our own, but the latest DataDog statsd v5 package has their own
	// in a `mocks` package there.
	"github.com/mozilla-services/autograph/internal/mockstatsd"
	"go.uber.org/mock/gomock"
)

func TestStatsResponseWriterWritesResponseMetricOnce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStats := mockstatsd.NewMockClientInterface(ctrl)
	mockStats.EXPECT().Incr("myhandler.response.status.4xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.success", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.status.400", []string(nil), 1.0).Times(1)

	recorder := httptest.NewRecorder()
	statsWriter := newStatsdWriter(recorder, "myhandler", mockStats)
	statsWriter.WriteHeader(http.StatusBadRequest)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status code %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	statsWriter.WriteHeader(http.StatusCreated)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tried to write to the headers again: Expected status code %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestStatsResponseWriterWritesToHeaderOnWrite(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStats := mockstatsd.NewMockClientInterface(ctrl)
	mockStats.EXPECT().Incr("myhandler.response.status.2xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.success", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.status.200", []string(nil), 1.0).Times(1)

	recorder := httptest.NewRecorder()
	statsWriter := newStatsdWriter(recorder, "myhandler", mockStats)
	statsWriter.Write([]byte("hello"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestWrappingStatsResponseWriteWritesAllMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStats := mockstatsd.NewMockClientInterface(ctrl)
	mockStats.EXPECT().Incr("inner.response.status.5xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("inner.response.status.500", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("wrapper.response.status.5xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("wrapper.response.status.500", []string(nil), 1.0).Times(1)

	recorder := httptest.NewRecorder()
	inner := newStatsdWriter(recorder, "inner", mockStats)
	wrapper := newStatsdWriter(inner, "wrapper", mockStats)

	wrapper.WriteHeader(http.StatusInternalServerError)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
}

func TestPromResponseWriterWritesResponseMetricOnce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStats := mockstatsd.NewMockClientInterface(ctrl)
	mockStats.EXPECT().Incr("myhandler.response.status.4xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.success", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.status.400", []string(nil), 1.0).Times(1)

	recorder := httptest.NewRecorder()
	statsWriter := newStatsdWriter(recorder, "myhandler", mockStats)
	statsWriter.WriteHeader(http.StatusBadRequest)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status code %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	statsWriter.WriteHeader(http.StatusCreated)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tried to write to the headers again: Expected status code %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestPromResponseWriterWritesToHeaderOnWrite(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStats := mockstatsd.NewMockClientInterface(ctrl)
	mockStats.EXPECT().Incr("myhandler.response.status.2xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.success", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("myhandler.response.status.200", []string(nil), 1.0).Times(1)

	recorder := httptest.NewRecorder()
	statsWriter := newStatsdWriter(recorder, "myhandler", mockStats)
	statsWriter.Write([]byte("hello"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestWrappingPromResponseWriteWritesAllMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStats := mockstatsd.NewMockClientInterface(ctrl)
	mockStats.EXPECT().Incr("inner.response.status.5xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("inner.response.status.500", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("wrapper.response.status.5xx", []string(nil), 1.0).Times(1)
	mockStats.EXPECT().Incr("wrapper.response.status.500", []string(nil), 1.0).Times(1)

	recorder := httptest.NewRecorder()
	inner := newStatsdWriter(recorder, "inner", mockStats)
	wrapper := newStatsdWriter(inner, "wrapper", mockStats)

	wrapper.WriteHeader(http.StatusInternalServerError)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
}