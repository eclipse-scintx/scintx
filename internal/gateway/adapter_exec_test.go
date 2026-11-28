// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/adapter"
	"github.com/eclipse-scintx/scintx/adapter/ossindex"
	"github.com/eclipse-scintx/scintx/adapter/osv"
	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// TestOrchestratorWithOSVAdapter verifies that NewOrchestratorWithAdapters
// executes the OSV adapter on PURL submissions, retries transient 429
// responses, and fails closed on unsupported digest-only artifacts (#94, #97).
func TestOrchestratorWithOSVAdapter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","database_specific":{"severity":"HIGH"}}]}`))
	}))
	defer srv.Close()

	store := NewMemoryStore()
	osvAdapter := osv.NewAdapter(osv.Config{BaseURL: srv.URL}, srv.Client())
	orch := newOrchestrator(config.Default(), store, func(o *Orchestrator) {
		o.adapters = []adapter.ProviderAdapter{osvAdapter}
		o.retryBackoff = 0
		o.pollInterval = 10 * time.Millisecond
	})
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if got.Attempts != 2 || len(got.Reports) != 1 {
		t.Fatalf("expected 2 attempts and 1 OSV report after 429 retry, got attempts=%d reports=%d", got.Attempts, len(got.Reports))
	}
	var rep adapter.ProviderReport
	if err := json.Unmarshal(got.Reports[0], &rep); err != nil || rep.Provider != osv.AdapterSlug {
		t.Fatalf("unexpected OSV report: %+v err=%v", rep, err)
	}
	// Check the finding itself, not only how many there are.
	if ids := vulnFindingIDs(t, got.Reports[0]); len(ids) != 1 || ids[0] != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("unexpected normalized findings on submission: %v", ids)
	}

	// Verify that a digest-only submission fails closed on attempt 1 with provenance.
	digestSub := mustSubmit(t, orch, api.ArtifactInput{
		Digest: &api.Digest{Algorithm: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	})
	if fd := waitForStatus(t, store, digestSub.ID, api.SubmissionFailed); fd.Attempts != 1 || fd.Error == "" || len(fd.Reports) != 1 {
		t.Fatalf("expected 1 attempt and 1 provenance report on unsupported digest, got %+v", fd)
	}
}

// TestOrchestratorWithOSVAndOSSIndexAdapters verifies multi-adapter successful
// responses, empty results, single-provider ecosystem routing, and unsupported
// PURL ecosystems across both OSV and OSS Index (#43, #96, #97).
func TestOrchestratorWithOSVAndOSSIndexAdapters(t *testing.T) {
	var cleanMode atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/query":
			if cleanMode.Load() {
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection","database_specific":{"severity":"HIGH"}}]}`))
		case "/api/v3/component-report":
			if cleanMode.Load() {
				_, _ = w.Write([]byte(`[{"coordinates":"pkg:npm/lodash@4.17.21","vulnerabilities":[]}]`))
				return
			}
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

	// 1. Vulnerable package across both providers.
	sub := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted); len(got.Reports) != 2 {
		t.Fatalf("expected 2 provider reports (osv + ossindex), got %d", len(got.Reports))
	}

	// 2. Clean package (empty findings) across both providers (#97).
	cleanMode.Store(true)
	cleanSub := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"})
	cleanGot := waitForStatus(t, store, cleanSub.ID, api.SubmissionCompleted)
	if len(cleanGot.Reports) != 2 {
		t.Fatalf("expected 2 clean provider reports, got %d", len(cleanGot.Reports))
	}
	// A clean package must carry no findings, not just two reports.
	for _, raw := range cleanGot.Reports {
		if ids := vulnFindingIDs(t, raw); len(ids) != 0 {
			t.Fatalf("expected no findings on clean package, got %v in %s", ids, raw)
		}
	}

	// 3. Ecosystem supported only by OSV (vscode-extension) skips OSS Index (#96, #97).
	vsxSub := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:vscode-extension/acme/theme-pro@1.0.2?repository_url=https://open-vsx.org"})
	if got := waitForStatus(t, store, vsxSub.ID, api.SubmissionCompleted); len(got.Reports) != 1 {
		t.Fatalf("expected 1 report (osv only) for vscode-extension, got %d", len(got.Reports))
	}

	// 4. Unsupported PURL ecosystem (pkg:generic) fails closed with ecosystem reason (#97).
	genSub := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:generic/foo@1.0.0"})
	if fg := waitForStatus(t, store, genSub.ID, api.SubmissionFailed); fg.Attempts != 1 || len(fg.Reports) != 2 || !strings.Contains(string(fg.Reports[0]), `PURL ecosystem \"generic\"`) {
		t.Fatalf("expected 2 provenance reports naming generic ecosystem, got %s", string(fg.Reports[0]))
	}
}

type panicTestAdapter struct{ osv.Adapter }

func (p *panicTestAdapter) Evaluate(_ context.Context, _ adapter.EvaluationRequest) (*adapter.EvaluationResult, error) {
	panic("simulated child goroutine adapter panic")
}

// TestConcurrentAdapterPanicAndAdversarialFailures verifies permanent auth/malformed
// failure precedence, persistent 429 retry exhaustion, and child goroutine panic recovery (#97).
func TestConcurrentAdapterPanicAndAdversarialFailures(t *testing.T) {
	var mode atomic.Value
	mode.Store("auth-vs-429")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load().(string) {
		case "auth-vs-429":
			if r.URL.Path == "/v1/query" {
				w.WriteHeader(http.StatusTooManyRequests)
			} else {
				w.WriteHeader(http.StatusPaymentRequired)
			}
		case "always-429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "malformed":
			_, _ = w.Write([]byte(`not-json`))
		}
	}))
	defer srv.Close()

	store := NewMemoryStore()
	osvAdapter := osv.NewAdapter(osv.Config{BaseURL: srv.URL}, srv.Client())
	ossAdapter := ossindex.NewAdapter(ossindex.Config{BaseURL: srv.URL, Token: "bad-pat"}, srv.Client())
	orch := newOrchestrator(config.Default(), store, func(o *Orchestrator) {
		o.adapters = []adapter.ProviderAdapter{osvAdapter, ossAdapter}
		o.retryBackoff = 0
		o.pollInterval = 10 * time.Millisecond
	})

	// 1. Permanent 402 on OSS Index takes precedence over 429 on OSV (no retries).
	sub1 := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if f1 := waitForStatus(t, store, sub1.ID, api.SubmissionFailed); f1.Attempts != 1 || len(f1.Reports) != 2 {
		t.Fatalf("expected 1 attempt and 2 reports on 402+429, got attempts=%d reports=%d", f1.Attempts, len(f1.Reports))
	}

	// 2. Malformed upstream JSON fails on attempt 1 without retry.
	mode.Store("malformed")
	sub2 := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if f2 := waitForStatus(t, store, sub2.ID, api.SubmissionFailed); f2.Attempts != 1 || !strings.Contains(string(f2.Reports[0]), string(adapter.ErrMalformedResponse)) {
		t.Fatalf("expected 1 attempt with malformed_provider_response, got attempts=%d", f2.Attempts)
	}

	// 3. Persistent 429 exhausts DefaultMaxAttempts (3) and transitions to failed.
	mode.Store("always-429")
	sub3 := mustSubmit(t, orch, api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if f3 := waitForStatus(t, store, sub3.ID, api.SubmissionFailed); f3.Attempts != DefaultMaxAttempts || !strings.Contains(string(f3.Reports[0]), string(adapter.ErrRateLimited)) {
		t.Fatalf("expected %d attempts on persistent 429, got attempts=%d", DefaultMaxAttempts, f3.Attempts)
	}
	orch.Shutdown()

	// 4. Child adapter goroutine panic is recovered and records provenance.
	panicStore := NewMemoryStore()
	panicOrch := newOrchestrator(config.Default(), panicStore, func(o *Orchestrator) {
		o.adapters = []adapter.ProviderAdapter{&panicTestAdapter{Adapter: *osvAdapter}}
	})
	defer panicOrch.Shutdown()
	pSub := mustSubmit(t, panicOrch, api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if pf := waitForStatus(t, panicStore, pSub.ID, api.SubmissionFailed); pf.Error != "internal execution error" || len(pf.Reports) != 1 {
		t.Fatalf("expected internal execution error and 1 provenance report on panic, got err=%q reports=%d", pf.Error, len(pf.Reports))
	}
}
