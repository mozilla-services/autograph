package main

import (
	"net/http"
	"testing"
)

func Test_defaultX5UClient(t *testing.T) {
	tests := []struct {
		name string
		want *http.Client
	}{
		{
			name: "builds test client with 5 minute timeout",
			want: &http.Client{
				Timeout: DefaultHTTPClientTimeout,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultX5UClient()
			if got.Timeout != tt.want.Timeout {
				t.Errorf("defaultX5UClient().Timeout = %v, want %v", got, tt.want)
			}
		})
	}
}
