package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// config params from
// https://github.com/aws/aws-sdk-go-v2/blob/main/aws/transport/http/client.go#L12-L25
// (Apache v2 licensed)

// Defaults for the HTTPTransportBuilder.
var (
	// Default connection pool options
	DefaultHTTPTransportMaxIdleConns        = 100
	DefaultHTTPTransportMaxIdleConnsPerHost = 10

	// Default connection timeouts
	DefaultHTTPTransportIdleConnTimeout       = 90 * time.Second
	DefaultHTTPTransportTLSHandleshakeTimeout = 10 * time.Second
	DefaultHTTPTransportExpectContinueTimeout = 1 * time.Second

	// Default to TLS 1.2 for all HTTPS requests.
	DefaultHTTPTransportTLSMinVersion uint16 = tls.VersionTLS12
)

// Timeouts for net.Dialer's network connection.
var (
	DefaultDialConnectTimeout   = 30 * time.Second
	DefaultDialKeepAliveTimeout = 30 * time.Second
)

// DefaultHTTPClientTimeout is the http.Client timeout for the
// defaultX5UClient
var DefaultHTTPClientTimeout = 5 * time.Minute

// defaultX5UClient
func defaultX5UClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   DefaultDialConnectTimeout,
		KeepAlive: DefaultDialKeepAliveTimeout,
		// try IPv4 if IPv6 appears to be misconfigured and hanging
		DualStack: true,
	}
	return &http.Client{
		Timeout: DefaultHTTPClientTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   DefaultHTTPTransportTLSHandleshakeTimeout,
			MaxIdleConns:          DefaultHTTPTransportMaxIdleConns,
			MaxIdleConnsPerHost:   DefaultHTTPTransportMaxIdleConnsPerHost,
			IdleConnTimeout:       DefaultHTTPTransportIdleConnTimeout,
			ExpectContinueTimeout: DefaultHTTPTransportExpectContinueTimeout,
			ForceAttemptHTTP2:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: DefaultHTTPTransportTLSMinVersion,
			},
		},
	}
}
