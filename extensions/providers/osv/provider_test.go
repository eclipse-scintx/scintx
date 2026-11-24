// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package osv_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/extensions/providers/osv"
)

func TestOSVAdapter_EvaluateAndVSCodeFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"vulns": [{
				"id": "GHSA-35jh-r3h4-6jhm",
				"summary": "Command Injection in lodash",
				"aliases": ["CVE-2021-23337"],
				"database_specific": {"severity": "CRITICAL"}
			}]
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	adapter := osv.NewAdapter(osv.Config{BaseURL: srv.URL}, srv.Client())
	status := adapter.CheckAvailability(context.Background())
	if !status.Available || status.State != api.StateReady {
		t.Fatalf("expected adapter ready, got %+v", status)
	}

	res, err := adapter.Evaluate(context.Background(), api.EvaluationRequest{
		SubmissionID:  "sub-1",
		ProviderRunID: "run-1",
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	})
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}
	vulnCap := res.Report.Capabilities[api.CapabilityVulnerabilities]
	if vulnCap.Status != api.CapabilityStatusCompleted || len(vulnCap.Findings) != 1 {
		t.Fatalf("expected 1 vulnerability finding, got %+v", vulnCap)
	}
	if vulnCap.Findings[0].Severity != api.SeverityCritical {
		t.Fatalf("got severity %q, want critical", vulnCap.Findings[0].Severity)
	}
}

func TestOSVAdapter_MalformedResponseAndRateLimit(t *testing.T) {
	code := http.StatusTooManyRequests
	body := `not-json`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	adapter := osv.NewAdapter(osv.Config{BaseURL: srv.URL}, srv.Client())
	_, err := adapter.Evaluate(context.Background(), api.EvaluationRequest{
		Artifact: api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
	})
	var aerr *api.AdapterError
	if !errors.As(err, &aerr) || aerr.Code != api.ErrRateLimited {
		t.Fatalf("expected rate_limited error, got %v", err)
	}

	code = http.StatusOK
	_, err = adapter.Evaluate(context.Background(), api.EvaluationRequest{
		Artifact: api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
	})
	if !errors.As(err, &aerr) || aerr.Code != api.ErrMalformedResponse {
		t.Fatalf("expected malformed_provider_response error, got %v", err)
	}
}
