// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package e2e verifies the Eclipse SCINTX gateway workflow:
// startup, liveness/readiness probes, valid artifact submission, status
// retrieval, and validation failure.
package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
	"github.com/yeeth-security/scintx/internal/server"
)

func TestGatewayE2E(t *testing.T) {
	cfg := config.Default()
	store := gateway.NewStore()
	orch := gateway.NewOrchestrator(cfg, store)
	srv := server.New(cfg, store, orch)

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	// 1. Verify liveness (/healthz) and readiness (/readyz).
	for _, endpoint := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + endpoint)
		if err != nil {
			t.Fatalf("GET %s: %v", endpoint, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%d, want 200", endpoint, resp.StatusCode)
		}
	}

	// 2. Submit valid artifact and poll status.
	subReq := []byte(`{"artifact":{"purl":"pkg:npm/lodash@4.17.20"}}`)
	resp, err := http.Post(ts.URL+"/v1/submissions", "application/json", bytes.NewReader(subReq))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /v1/submissions status=%d, want 202", resp.StatusCode)
	}
	var created api.Submission
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	// 3. Retrieve status.
	statusResp, err := http.Get(ts.URL + "/v1/submissions/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer statusResp.Body.Close()
	var polled api.Submission
	if err := json.NewDecoder(statusResp.Body).Decode(&polled); err != nil {
		t.Fatal(err)
	}
	if polled.Status != api.SubmissionCompleted {
		t.Fatalf("status=%q, want completed", polled.Status)
	}

	// 4. Verify validation failure on invalid artifact input (422).
	badReq := []byte(`{"artifact":{"purl":"invalid-purl"}}`)
	badResp, err := http.Post(ts.URL+"/v1/submissions", "application/json", bytes.NewReader(badReq))
	if err != nil {
		t.Fatal(err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on invalid purl, got %d", badResp.StatusCode)
	}
}
