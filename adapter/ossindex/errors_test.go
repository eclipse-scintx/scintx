// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package ossindex

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/adapter"
)

func TestEmptyResultAnonymousMirrorAndCVSSScale(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// Verify AllowAnonymous mode for local mirrors/mocks and empty findings handling (#95, #97).
	a := NewAdapter(Config{BaseURL: srv.URL, AllowAnonymous: true}, srv.Client())
	for _, payload := range []string{
		`[{"coordinates":"pkg:npm/lodash@4.17.21","vulnerabilities":[]}]`,
		`[{"coordinates":"pkg:npm/lodash@4.17.21"}]`,
	} {
		body = payload
		res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
			SubmissionID: "sub-clean", ProviderRunID: "run-clean",
			Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
			RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
		})
		if err != nil {
			t.Fatalf("payload %s: Evaluate failed: %v", payload, err)
		}
		check := res.Report.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities]
		if check.Status != adapter.CheckStatusEvaluated || check.Findings == nil || len(check.Findings) != 0 {
			t.Fatalf("payload %s: expected empty non-nil findings slice, got %+v", payload, check)
		}
	}

	score := func(v float64) *float64 { return &v }
	for _, tc := range []struct {
		vuln Vulnerability
		want adapter.Severity
	}{
		{Vulnerability{ID: "V-CRIT", CVSSScore: score(9.8)}, adapter.SeverityCritical},
		{Vulnerability{ID: "V-HIGH", CVSSScore: score(7.5)}, adapter.SeverityHigh},
		{Vulnerability{ID: "V-MED", CVSSScore: score(5.3)}, adapter.SeverityMedium},
		{Vulnerability{ID: "V-LOW", CVSSScore: score(2.1)}, adapter.SeverityLow},
		{Vulnerability{ID: "V-INFO", CVSSScore: score(0.0)}, adapter.SeverityInfo},
		{Vulnerability{ID: "V-UNK"}, adapter.SeverityUnknown},
	} {
		if got := extractSeverity(tc.vuln); got != tc.want {
			t.Errorf("%s: extractSeverity = %q, want %q", tc.vuln.ID, got, tc.want)
		}
	}
}

func TestCheckAvailabilityStates(t *testing.T) {
	if st := NewAdapter(Config{BaseURL: "://bad", Token: "pat"}, nil).CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Available || st.Reasons[0] != adapter.ReasonInvalidConfiguration {
		t.Fatalf("expected unconfigured for invalid URL, got %+v", st)
	}
	if st := NewAdapter(Config{BaseURL: DefaultBaseURL}, nil).CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Reasons[0] != adapter.ReasonMissingCredentials {
		t.Fatalf("expected missing_credentials when token is empty, got %+v", st)
	}

	// Upstream HTTP 200, 401, 402 (Sonatype Guide cutover auth failure), 403, 429, 503, and closed server.
	var statusCode int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(statusCode) }))
	a := NewAdapter(Config{BaseURL: srv.URL, Token: "pat"}, srv.Client())

	statusCode = http.StatusOK
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateReady || !st.Available {
		t.Fatalf("expected ready on 200, got %+v", st)
	}
	statusCode = http.StatusTooManyRequests
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateDegraded || !st.Available || st.Reasons[0] != adapter.ReasonRateLimited {
		t.Fatalf("expected degraded/available on 429, got %+v", st)
	}
	for _, authStatus := range []int{http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden} {
		statusCode = authStatus
		if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonAuthenticationFailed {
			t.Fatalf("HTTP %d: expected authentication_failed, got %+v", authStatus, st)
		}
	}
	statusCode = http.StatusServiceUnavailable
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonUpstreamUnreachable {
		t.Fatalf("expected unreachable on 503, got %+v", st)
	}
	srv.Close()
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonUpstreamUnreachable {
		t.Fatalf("expected unreachable on closed server, got %+v", st)
	}
}

func TestEvaluateErrorClassification(t *testing.T) {
	validReq := adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	}

	// 1. Missing credentials and invalid BaseURL fail closed without network calls (#97).
	var ae *adapter.AdapterError
	if _, err := NewAdapter(Config{}, nil).Evaluate(context.Background(), validReq); !errors.As(err, &ae) || ae.Code != adapter.ErrAuthFailed || ae.Retryable {
		t.Fatalf("expected non-retryable ErrAuthFailed without credentials, got %v", err)
	}
	if _, err := NewAdapter(Config{BaseURL: "://bad", Token: "pat"}, nil).Evaluate(context.Background(), validReq); !errors.As(err, &ae) || ae.Code != adapter.ErrUpstreamUnavailable || ae.Retryable {
		t.Fatalf("expected non-retryable ErrUpstreamUnavailable on invalid BaseURL, got %v", err)
	}

	// 2. Unsupported input forms: empty, digest-only, content-only, unversioned, missing namespace, range, unsupported ecosystem/capability (#97).
	a := NewAdapter(Config{Token: "pat"}, nil)
	for i, req := range []adapter.EvaluationRequest{
		{Artifact: adapter.ArtifactInput{}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{Digest: &adapter.Digest{Algorithm: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{ContentMeta: &adapter.ContentMetadata{Filename: "app.tar.gz"}}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:maven/commons-text@1.9"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@^4.17.0"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@%5B4.0.0%2C4.17.20%29"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:generic/foo@1.0.0"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:vscode-extension/acme/ext@1.0.0"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityThreats}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityLicenses}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: nil},
	} {
		if _, bErr := a.Evaluate(context.Background(), req); !errors.As(bErr, &ae) || ae.Code != adapter.ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("case %d: expected non-retryable ErrUnsupportedInput, got %v", i, bErr)
		}
	}

	// 3. Upstream HTTP 401/402/403/429/400/502, malformed responses, timeout, and closed server (#97).
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode {
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
		case "402":
			w.WriteHeader(http.StatusPaymentRequired)
		case "403":
			w.WriteHeader(http.StatusForbidden)
		case "429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "400":
			w.WriteHeader(http.StatusBadRequest)
		case "502":
			w.WriteHeader(http.StatusBadGateway)
		case "bad-json":
			_, _ = w.Write([]byte(`not-json`))
		case "json-object":
			_, _ = w.Write([]byte(`{"error":"unexpected object"}`))
		case "empty-array":
			_, _ = w.Write([]byte(`[]`))
		case "missing-id":
			_, _ = w.Write([]byte(`[{"coordinates":"pkg:npm/lodash@4.17.20","vulnerabilities":[{"title":"no id"}]}]`))
		case "slow":
			time.Sleep(80 * time.Millisecond)
		}
	}))
	clientAdapter := NewAdapter(Config{BaseURL: srv.URL, Token: "pat"}, srv.Client())

	for _, tc := range []struct {
		m     string
		want  adapter.ErrorCode
		retry bool
	}{
		{"401", adapter.ErrAuthFailed, false}, {"402", adapter.ErrAuthFailed, false}, {"403", adapter.ErrAuthFailed, false},
		{"429", adapter.ErrRateLimited, true}, {"400", adapter.ErrUpstreamUnavailable, false}, {"502", adapter.ErrUpstreamUnavailable, true},
		{"bad-json", adapter.ErrMalformedResponse, false}, {"json-object", adapter.ErrMalformedResponse, false},
		{"empty-array", adapter.ErrMalformedResponse, false}, {"missing-id", adapter.ErrMalformedResponse, false},
	} {
		mode = tc.m
		if _, cErr := clientAdapter.Evaluate(context.Background(), validReq); !errors.As(cErr, &ae) || ae.Code != tc.want || ae.Retryable != tc.retry {
			t.Fatalf("mode %s: got err=%+v, want code=%s retryable=%v", tc.m, cErr, tc.want, tc.retry)
		}
	}

	mode = "slow"
	tctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if _, err := clientAdapter.Evaluate(tctx, validReq); !errors.As(err, &ae) || ae.Code != adapter.ErrTimeout || !ae.Retryable {
		t.Fatalf("expected retryable ErrTimeout, got %v", err)
	}
	srv.Close()
	if _, err := clientAdapter.Evaluate(context.Background(), validReq); !errors.As(err, &ae) || ae.Code != adapter.ErrUpstreamUnavailable || !ae.Retryable {
		t.Fatalf("expected retryable ErrUpstreamUnavailable on closed server, got %v", err)
	}
}
