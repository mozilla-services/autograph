package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMonitorNoConfig(t *testing.T) {
	t.Parallel()

	tmpag := newAutographer(1)
	var nomonitor configuration
	tmpag.addMonitoring(nomonitor.Monitoring)
	_, err := tmpag.getAuthByID(monitorAuthID)
	if err == nil {
		t.Fatal("monitor configuration found when none was passed")
	}
}

func TestMonitorAddDuplicate(t *testing.T) {
	t.Parallel()

	tmpag := newAutographer(1)
	var monitorconf configuration
	monitorconf.Monitoring.Key = "xxxxxxx"

	defer func() {
		if e := recover(); e != nil {
			if e != `user 'monitor' is reserved for monitoring, duplication is not permitted` {
				t.Fatalf("expected authorization loading to fail with duplicate error but got: %v", e)
			}
		}
	}()
	// Adding the first one will pass, adding the second one will trigger the panic
	tmpag.addMonitoring(monitorconf.Monitoring)
	tmpag.addMonitoring(monitorconf.Monitoring)
}

func TestMonitorBadRequest(t *testing.T) {
	t.Parallel()

	var TESTCASES = []struct {
		user     string
		key      string
		endpoint string
		method   string
		body     string
	}{
		// wrong method
		{``, ``, `/__monitor__`, `POST`, ``},
		{``, ``, `/__monitor__`, `PUT`, ``},
		{``, ``, `/__monitor__`, `HEAD`, ``},
		{``, ``, `/__monitor__`, `DELETE`, ``},
		// shouldn't have a request body
		{`monitor`, conf.Monitoring.Key, `/__monitor__`, `GET`, `[{"input":"y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"}]`},
		// should use the monitor user
		{conf.Authorizations[0].ID, conf.Authorizations[0].Key, `/__monitor__`, `GET`, ``},
		// should use the monitoring key
		{`monitor`, conf.Authorizations[0].Key, `/__monitor__`, `GET`, ``},
	}
	for i, testcase := range TESTCASES {
		body := strings.NewReader(testcase.body)
		req, err := http.NewRequest(testcase.method, "http://foo.bar"+testcase.endpoint, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		authheader := getAuthHeader(req, testcase.user, testcase.key, sha256.New, id(), "application/json", []byte(testcase.body))
		req.Header.Set("Authorization", authheader)
		w := httptest.NewRecorder()
		mo.handleMonitor(w, req)
		if w.Code == http.StatusCreated {
			t.Fatalf("test case %d failed with %d: %s", i, w.Code, w.Body.String())
		}
	}
}
