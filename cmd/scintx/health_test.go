// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReadyzURL checks how the listen address becomes the probe URL.
// Wildcard bind addresses cannot be dialed, so they must become 127.0.0.1.
func TestReadyzURL(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"empty uses the default port", "", "http://127.0.0.1:8080/readyz"},
		{"only a port", ":9090", "http://127.0.0.1:9090/readyz"},
		{"ipv4 wildcard", "0.0.0.0:8080", "http://127.0.0.1:8080/readyz"},
		{"ipv6 wildcard", "[::]:8080", "http://127.0.0.1:8080/readyz"},
		{"specific host is kept", "10.1.2.3:8080", "http://10.1.2.3:8080/readyz"},
		{"name is kept", "localhost:8080", "http://localhost:8080/readyz"},
		{"spaces are trimmed", "  :7070  ", "http://127.0.0.1:7070/readyz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readyzURL(tt.addr); got != tt.want {
				t.Fatalf("readyzURL(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// TestRunHealth runs the probe against a fake server. A 200 passes. Any
// other status must be an error, so the container is marked unhealthy.
func TestRunHealth(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := runHealth([]string{ok.URL + "/readyz"}); err != nil {
		t.Fatalf("expected a healthy result, got %v", err)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	if err := runHealth([]string{down.URL + "/readyz"}); err == nil {
		t.Fatal("expected an error for HTTP 503")
	}
}
