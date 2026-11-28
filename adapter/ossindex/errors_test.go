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

func TestEmptyResultAndCVSSSeverityScale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"coordinates":"pkg:npm/lodash@4.17.21","vulnerabilities":[]}]`))
	}))
	defer srv.Close()

	a := NewAdapter(Config{BaseURL: srv.URL, Token: "pat"}, srv.Client())
	res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		SubmissionID:          "sub-clean",
		ProviderRunID:         "run-clean",
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	})
	if err != nil {
		t.Fatalf("Evaluate failed on empty result: %v", err)
	}
	check := res.Report.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities]
	if check.Status != adapter.CheckStatusEvaluated || check.Findings == nil || len(check.Findings) != 0 {
		t.Fatalf("expected empty non-nil findings slice, got %+v", check)
	}

	score := func(v float64) *float64 { return &v }
	cases := []struct {
		vuln Vulnerability
		want adapter.Severity
	}{
		{Vulnerability{ID: "V-CRIT", CVSSScore: score(9.8)}, adapter.SeverityCritical},
		{Vulnerability{ID: "V-HIGH", CVSSScore: score(7.5)}, adapter.SeverityHigh},
		{Vulnerability{ID: "V-MED", CVSSScore: score(5.3)}, adapter.SeverityMedium},
		{Vulnerability{ID: "V-LOW", CVSSScore: score(2.1)}, adapter.SeverityLow},
		{Vulnerability{ID: "V-INFO", CVSSScore: score(0.0)}, adapter.SeverityInfo},
		{Vulnerability{ID: "V-UNK"}, adapter.SeverityUnknown},
	}
	for _, tc := range cases {
		if got := extractSeverity(tc.vuln); got != tc.want {
			t.Errorf("%s: extractSeverity = %q, want %q", tc.vuln.ID, got, tc.want)
		}
	}
}

func TestCheckAvailabilityStates(t *testing.T) {
	// 1. Invalid URL
	badURL := NewAdapter(Config{BaseURL: "://bad", Token: "pat"}, nil)
	if st := badURL.CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Available || st.Reasons[0] != adapter.ReasonInvalidConfiguration {
		t.Fatalf("expected unconfigured for invalid URL, got %+v", st)
	}

	// 2. Missing credentials when AllowAnonymous is false
	noCreds := NewAdapter(Config{BaseURL: DefaultBaseURL}, nil)
	if st := noCreds.CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Reasons[0] != adapter.ReasonMissingCredentials {
		t.Fatalf("expected missing_credentials when token is empty, got %+v", st)
	}

	// 3. Upstream HTTP 200, 401, 402 (Sonatype Guide cutover auth failure), 429, 503
	var statusCode int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
	}))
	defer srv.Close()

	a := NewAdapter(Config{BaseURL: srv.URL, Token: "pat"}, srv.Client())
	statusCode = http.StatusOK
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateReady || !st.Available {
		t.Fatalf("expected ready on 200, got %+v", st)
	}
	statusCode = http.StatusTooManyRequests
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateDegraded || !st.Available || st.Reasons[0] != adapter.ReasonRateLimited {
		t.Fatalf("expected degraded/available on 429, got %+v", st)
	}
	for _, authStatus := range []int{http.StatusUnauthorized, http.StatusPaymentRequired} {
		statusCode = authStatus
		if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonAuthenticationFailed {
			t.Fatalf("HTTP %d: expected authentication_failed, got %+v", authStatus, st)
		}
	}
	statusCode = http.StatusServiceUnavailable
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonUpstreamUnreachable {
		t.Fatalf("expected unreachable on 503, got %+v", st)
	}
}

func TestEvaluateErrorClassification(t *testing.T) {
	// Missing credentials fails with non-retryable ErrAuthFailed.
	unauthed := NewAdapter(Config{}, nil)
	_, err := unauthed.Evaluate(context.Background(), adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	})
	var ae *adapter.AdapterError
	if !errors.As(err, &ae) || ae.Code != adapter.ErrAuthFailed || ae.Retryable {
		t.Fatalf("expected non-retryable ErrAuthFailed without credentials, got %v", err)
	}

	// Unsupported input forms: empty PURL, unversioned PURL, missing namespace, version range, unsupported ecosystem, unsupported capability.
	a := NewAdapter(Config{Token: "pat"}, nil)
	badReqs := []adapter.EvaluationRequest{
		{Artifact: adapter.ArtifactInput{}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:maven/commons-text@1.9"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@%5B4.0.0%2C4.17.20%29"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:generic/foo@1.0.0"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityLicenses}},
	}
	for i, req := range badReqs {
		_, bErr := a.Evaluate(context.Background(), req)
		if !errors.As(bErr, &ae) || ae.Code != adapter.ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("case %d: expected non-retryable ErrUnsupportedInput, got %v", i, bErr)
		}
	}

	// Upstream HTTP 401, 402, 429, 502, invalid JSON, missing ID, and timeout.
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode {
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
		case "402":
			w.WriteHeader(http.StatusPaymentRequired)
		case "429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "502":
			w.WriteHeader(http.StatusBadGateway)
		case "bad-json":
			_, _ = w.Write([]byte(`not-json`))
		case "empty-array":
			_, _ = w.Write([]byte(`[]`))
		case "missing-id":
			_, _ = w.Write([]byte(`[{"coordinates":"pkg:npm/lodash@4.17.20","vulnerabilities":[{"title":"no id"}]}]`))
		case "slow":
			time.Sleep(80 * time.Millisecond)
		}
	}))
	defer srv.Close()

	clientAdapter := NewAdapter(Config{BaseURL: srv.URL, Token: "pat"}, srv.Client())
	validReq := adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	}

	expectCode := func(m string, want adapter.ErrorCode, wantRetry bool) {
		t.Helper()
		mode = m
		_, cErr := clientAdapter.Evaluate(context.Background(), validReq)
		if !errors.As(cErr, &ae) || ae.Code != want || ae.Retryable != wantRetry {
			t.Fatalf("mode %s: got err=%+v, want code=%s retryable=%v", m, cErr, want, wantRetry)
		}
	}

	expectCode("401", adapter.ErrAuthFailed, false)
	expectCode("402", adapter.ErrAuthFailed, false)
	expectCode("429", adapter.ErrRateLimited, true)
	expectCode("502", adapter.ErrUpstreamUnavailable, true)
	expectCode("bad-json", adapter.ErrMalformedResponse, false)
	expectCode("empty-array", adapter.ErrMalformedResponse, false)
	expectCode("missing-id", adapter.ErrMalformedResponse, false)

	mode = "slow"
	tctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	_, err = clientAdapter.Evaluate(tctx, validReq)
	if !errors.As(err, &ae) || ae.Code != adapter.ErrTimeout || !ae.Retryable {
		t.Fatalf("expected retryable ErrTimeout, got %v", err)
	}
}
