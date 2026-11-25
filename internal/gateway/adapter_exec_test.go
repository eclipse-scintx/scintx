// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/eclipse-scintx/scintx/adapter"
	"github.com/eclipse-scintx/scintx/adapter/osv"
	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// TestOrchestratorWithOSVAdapter verifies that NewOrchestratorWithAdapters
// executes the OSV adapter on PURL submissions, attaches the normalized
// ProviderReport to Submission.Reports, retries 429 responses, and fails closed
// on unsupported digest-only artifacts.
func TestOrchestratorWithOSVAdapter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"vulns": [{
				"id": "GHSA-35jh-r3h4-6jhm",
				"summary": "Command Injection in lodash",
				"database_specific": {"severity": "HIGH"}
			}]
		}`))
	}))
	defer srv.Close()

	store := NewMemoryStore()
	osvAdapter := osv.NewAdapter(osv.Config{
		BaseURL: srv.URL,
	}, srv.Client())
	orch := newOrchestrator(
		config.Default(),
		store,
		func(o *Orchestrator) {
			o.adapters = []adapter.ProviderAdapter{osvAdapter}
			o.retryBackoff = 0
		},
	)
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{
		PURL: "pkg:npm/lodash@4.17.20",
	})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if got.Attempts != 2 {
		t.Fatalf("expected 2 attempts after 429 retry, got %d", got.Attempts)
	}
	if len(got.Reports) != 1 {
		t.Fatalf("expected 1 OSV report on completed submission, got %d", len(got.Reports))
	}
	var rep adapter.ProviderReport
	if err := json.Unmarshal(got.Reports[0], &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if rep.Provider != osv.AdapterSlug {
		t.Fatalf("expected provider %q, got %q", osv.AdapterSlug, rep.Provider)
	}
	findings := rep.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities].Findings
	if len(findings) != 1 || findings[0].ID != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("unexpected normalized findings on submission: %+v", findings)
	}

	// Verify that a digest-only submission fails closed when only OSV (PURL-only) is configured.
	digestSub, err := orch.Submit(context.Background(), api.ArtifactInput{
		Digest: &api.Digest{
			Algorithm: "sha256",
			Value:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	})
	if err != nil {
		t.Fatalf("Submit digest failed: %v", err)
	}
	failedDigest := waitForStatus(t, store, digestSub.ID, api.SubmissionFailed)
	if failedDigest.Error == "" {
		t.Fatalf("expected non-empty error on unsupported digest submission")
	}
}
