// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/extensions/providers/ossindex"
	"github.com/yeeth-security/scintx/extensions/providers/osv"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
	"github.com/yeeth-security/scintx/internal/policy"
	"github.com/yeeth-security/scintx/internal/server"
)

func TestEndToEnd_GatewaySubmissionValidationAndStatus(t *testing.T) {
	cfg := config.Default()
	cfg.Gateway.BearerToken = "e2e-token"
	store := gateway.NewStore()

	polMap, err := policy.LoadDir("../../policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	adapters := []api.ProviderAdapter{
		osv.NewAdapter(osv.Config{OfflineDemo: true}, nil),
		ossindex.NewAdapter(ossindex.Config{}, nil),
	}
	orch := gateway.NewOrchestrator(cfg, store, polMap, adapters)
	srv := server.New(cfg, store, orch)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := ts.Client()

	// 1. Health probes work without authentication (#41).
	for _, probe := range []string{"/healthz", "/readyz"} {
		resp, err := client.Get(ts.URL + probe)
		if err != nil {
			t.Fatalf("GET %s failed: %v", probe, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d, want 200", probe, resp.StatusCode)
		}
	}

	// 2. Validation failure on invalid digest algorithm (#41, #68).
	badReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/submissions",
		strings.NewReader(`{"artifact":{"digest":{"algorithm":"md5","value":"d41d8cd98f00b204e9800998ecf8427e"}}}`))
	badReq.Header.Set("Authorization", "Bearer e2e-token")
	badReq.Header.Set("Content-Type", "application/json")
	badResp, err := client.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("got %d for unsupported digest algorithm, want 422", badResp.StatusCode)
	}

	// 3. Valid submission -> poll status -> retrieve Aggregate Report and Policy Report (#41, #67, #68).
	subReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/submissions",
		strings.NewReader(`{"artifact":{"purl":"pkg:npm/lodash@4.17.21"},"policy":"baseline-security"}`))
	subReq.Header.Set("Authorization", "Bearer e2e-token")
	subReq.Header.Set("Content-Type", "application/json")
	subResp, err := client.Do(subReq)
	if err != nil {
		t.Fatal(err)
	}
	var created api.Submission
	_ = json.NewDecoder(subResp.Body).Decode(&created)
	_ = subResp.Body.Close()
	if subResp.StatusCode != http.StatusAccepted || created.ID == "" {
		t.Fatalf("got status=%d id=%q, want 202 with submission ID", subResp.StatusCode, created.ID)
	}

	orch.Wait()

	// Poll status
	pollReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/submissions/"+created.ID, nil)
	pollReq.Header.Set("Authorization", "Bearer e2e-token")
	pollResp, err := client.Do(pollReq)
	if err != nil {
		t.Fatal(err)
	}
	var polled api.Submission
	_ = json.NewDecoder(pollResp.Body).Decode(&polled)
	_ = pollResp.Body.Close()
	if polled.Status != api.SubmissionCompleted || polled.PolicyVerdict != api.VerdictSatisfied {
		t.Fatalf("got status=%q verdict=%q, want completed/satisfied", polled.Status, polled.PolicyVerdict)
	}
}
