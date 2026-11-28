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
	"github.com/eclipse-scintx/scintx/adapter/ossindex"
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
	if failedDigest.Error == "" || len(failedDigest.Reports) != 1 {
		t.Fatalf("expected non-empty error and 1 provenance report on unsupported digest submission, got %+v", failedDigest)
	}
}

// TestOrchestratorWithOSVAndOSSIndexAdapters verifies that a submission is
// evaluated across both the OSV and OSS Index adapters (#43, #94, #95) and
// stores both normalized ProviderReports on the completed submission.
func TestOrchestratorWithOSVAndOSSIndexAdapters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/query":
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection","database_specific":{"severity":"HIGH"}}]}`))
		case "/api/v3/component-report":
			_, _ = w.Write([]byte(`[{"coordinates":"pkg:npm/lodash@4.17.20","vulnerabilities":[{"id":"sonatype-2021-0001","title":"Command Injection","cvssScore":7.4,"cve":"CVE-2021-23337"}]}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	store := NewMemoryStore()
	osvAdapter := osv.NewAdapter(osv.Config{BaseURL: srv.URL}, srv.Client())
	ossAdapter := ossindex.NewAdapter(ossindex.Config{BaseURL: srv.URL, Token: "guide-pat"}, srv.Client())
	orch := newOrchestrator(config.Default(), store, func(o *Orchestrator) {
		o.adapters = []adapter.ProviderAdapter{osvAdapter, ossAdapter}
	})
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if len(got.Reports) != 2 {
		t.Fatalf("expected 2 provider reports (osv + ossindex), got %d", len(got.Reports))
	}
}

type panicTestAdapter struct{ osv.Adapter }

func (p *panicTestAdapter) Evaluate(_ context.Context, _ adapter.EvaluationRequest) (*adapter.EvaluationResult, error) {
	panic("simulated child goroutine adapter panic")
}

// TestConcurrentAdapterPanicAndErrorPrecedence verifies that:
//  1. A panic inside a concurrent adapter goroutine is recovered by the worker
//     and marks the submission failed instead of crashing the process.
//  2. A permanent non-retryable error on one adapter takes precedence over a
//     retryable 429 error on another adapter so retries are not wasted.
func TestConcurrentAdapterPanicAndErrorPrecedence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/query":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/api/v3/component-report":
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	store := NewMemoryStore()
	osvAdapter := osv.NewAdapter(osv.Config{BaseURL: srv.URL}, srv.Client())
	ossAdapter := ossindex.NewAdapter(ossindex.Config{BaseURL: srv.URL, Token: "bad-pat"}, srv.Client())
	orch := newOrchestrator(config.Default(), store, func(o *Orchestrator) {
		o.adapters = []adapter.ProviderAdapter{osvAdapter, ossAdapter}
		o.retryBackoff = 0
	})
	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	failed := waitForStatus(t, store, sub.ID, api.SubmissionFailed)
	if failed.Attempts != 1 || len(failed.Reports) != 2 {
		t.Fatalf("expected permanent 401 on adapter 2 to prevent retry and keep 2 provenance reports, got attempts=%d reports=%d", failed.Attempts, len(failed.Reports))
	}
	orch.Shutdown()

	panicStore := NewMemoryStore()
	panicOrch := newOrchestrator(config.Default(), panicStore, func(o *Orchestrator) {
		o.adapters = []adapter.ProviderAdapter{&panicTestAdapter{Adapter: *osvAdapter}}
	})
	defer panicOrch.Shutdown()
	pSub, err := panicOrch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatalf("Submit panic sub failed: %v", err)
	}
	pFailed := waitForStatus(t, panicStore, pSub.ID, api.SubmissionFailed)
	if pFailed.Error != "internal execution error" || len(pFailed.Reports) != 1 {
		t.Fatalf("expected internal execution error and 1 provenance report on child adapter panic, got err=%q reports=%d", pFailed.Error, len(pFailed.Reports))
	}
}
