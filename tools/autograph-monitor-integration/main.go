package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

type stats struct {
	Attempts  int `json:"monitoring.attempts"`
	Successes int `json:"monitoring.successes"`
	Errors    int `json:"monitoring.errors"`
}

var (
	monitor = flag.String("name", "", "name of the monitor to check")
	baseURL = flag.String("url", "http://localhost:10000", "URL to check")
)

func main() {
	flag.Parse()
	monitorMetricsURL, err := url.JoinPath(*baseURL, "/debug/vars")
	if err != nil {
		log.Fatalf("failed to parse monitor URL %#v: %s", *baseURL, err)
	}
	var tryErr error
	for i := range 5 {
		fmt.Printf("try %d for monitor %#v at %#v\n", i, *monitor, monitorMetricsURL)
		tryErr = try(*monitor, monitorMetricsURL)
		if tryErr == nil {
			fmt.Println("success")
			break
		}
		time.Sleep(5 * time.Second)
	}
	if tryErr != nil {
		log.Fatal(tryErr)
	}
}

func try(monitorName, monitorMetricsURL string) error {
	resp, err := http.Get(monitorMetricsURL)
	if err != nil {
		return fmt.Errorf("failed to HTTP GET metrics from monitor at (%#v, %s): %s", monitorName, monitorMetricsURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read metrics response from monitor at (%#v, %s): %s", monitorName, monitorMetricsURL, err)
	}
	statResp := &stats{}
	err = json.Unmarshal(body, statResp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal metrics response from monitor (%#v, %s): %s", monitorName, monitorMetricsURL, err)
	}
	if statResp.Errors > 0 {
		return fmt.Errorf("non-zero monitoring errors detected from monitor at (%#v, %s): %d", monitorName, monitorMetricsURL, statResp.Errors)
	}
	if statResp.Attempts <= 0 {
		return fmt.Errorf("no monitoring attempts detected from monitor at (%#v, %s)", monitorName, monitorMetricsURL)
	}
	if statResp.Successes <= 0 {
		return fmt.Errorf("no monitoring successes detected from monitor at (%#v, %s)", monitorName, monitorMetricsURL)
	}
	return nil
}
