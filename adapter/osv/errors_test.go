// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/adapter"
)

func TestEmptyResultAndSeverityExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulns": []}`))
	}))
	defer srv.Close()

	a := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())
	res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		SubmissionID:          "sub-clean",
		ProviderRunID:         "run-clean",
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	capReport := res.Report.Capabilities[adapter.CapabilityVulnerabilities]
	check := capReport.Checks[adapter.CheckKnownVulnerabilities]
	if capReport.Status != adapter.CapabilityStatusCompleted || check.Status != adapter.CheckStatusEvaluated {
		t.Fatalf("unexpected clean status: cap=%q check=%q", capReport.Status, check.Status)
	}
	if check.Findings == nil || len(check.Findings) != 0 {
		t.Fatalf("expected non-nil empty findings slice, got %v", check.Findings)
	}

	// Verify severity fallbacks across ecosystem_specific, numeric CVSS, and unknown.
	cases := []struct {
		v    Vulnerability
		want adapter.Severity
	}{
		{Vulnerability{ID: "OSV-1", Affected: []AffectedEntry{{EcosystemSpecific: map[string]any{adapter.MetaKeySeverity: "MODERATE"}}}}, adapter.SeverityMedium},
		{Vulnerability{ID: "OSV-2", Affected: []AffectedEntry{{DatabaseSpecific: map[string]any{adapter.MetaKeySeverity: "LOW"}}}}, adapter.SeverityLow},
		{Vulnerability{ID: "OSV-3", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "9.8"}}}, adapter.SeverityCritical},
		{Vulnerability{ID: "OSV-4", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "7.5"}}}, adapter.SeverityHigh},
		{Vulnerability{ID: "OSV-5", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "5.4"}}}, adapter.SeverityMedium},
		{Vulnerability{ID: "OSV-6", Affected: []AffectedEntry{{Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "2.1"}}}}}, adapter.SeverityLow},
		{Vulnerability{ID: "OSV-7", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "0.0"}}}, adapter.SeverityInfo},
		{Vulnerability{ID: "OSV-8", DatabaseSpecific: map[string]any{adapter.MetaKeySeverity: "NONE"}}, adapter.SeverityInfo},
		{Vulnerability{ID: "DEBIAN-CVE-2021-3711", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}, adapter.SeverityCritical},
		{Vulnerability{ID: "DEBIAN-CVE-2021-3712", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H"}}}, adapter.SeverityHigh},
		{Vulnerability{ID: "DEBIAN-CVE-2021-4160", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}}}, adapter.SeverityMedium},
		{Vulnerability{ID: "GHSA-3h9f-r86x-qvjx", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"}}}, adapter.SeverityLow},
		{Vulnerability{ID: "GHSA-3pxv-7cmr-fjr4", Severity: []SeverityEntry{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N"}}}, adapter.SeverityMedium},
		{Vulnerability{ID: "UBUNTU-1", Affected: []AffectedEntry{{EcosystemSpecific: map[string]any{"urgency": "unimportant"}}}}, adapter.SeverityInfo},
		{Vulnerability{ID: "OSV-9"}, adapter.SeverityUnknown},
	}
	for _, tc := range cases {
		if got := extractSeverity(tc.v); got != tc.want {
			t.Errorf("extractSeverity(%s) = %q, want %q", tc.v.ID, got, tc.want)
		}
	}
}

func TestCheckAvailabilityStates(t *testing.T) {
	// 1. Invalid URL
	badURL := NewAdapter(Config{BaseURL: "://bad"}, nil)
	if st := badURL.CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Available || st.Reasons[0] != adapter.ReasonInvalidConfiguration {
		t.Fatalf("expected unconfigured for invalid URL, got %+v", st)
	}

	// 2. Missing required mirror token
	noAuth := NewAdapter(Config{BaseURL: "https://mirror.example.com", RequireAuth: true}, nil)
	if st := noAuth.CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Reasons[0] != adapter.ReasonMissingCredentials {
		t.Fatalf("expected missing_credentials, got %+v", st)
	}

	// 3. Upstream HTTP 200, 401, 429, 503
	var statusCode int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
	}))
	defer srv.Close()

	a := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())
	statusCode = http.StatusOK
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateReady || !st.Available {
		t.Fatalf("expected ready on 200, got %+v", st)
	}
	statusCode = http.StatusTooManyRequests
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateDegraded || !st.Available || st.Reasons[0] != adapter.ReasonRateLimited {
		t.Fatalf("expected degraded/available on 429, got %+v", st)
	}
	statusCode = http.StatusUnauthorized
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonAuthenticationFailed {
		t.Fatalf("expected authentication_failed on 401, got %+v", st)
	}
	statusCode = http.StatusServiceUnavailable
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonUpstreamUnreachable {
		t.Fatalf("expected unreachable on 503, got %+v", st)
	}
}

func TestEvaluateErrorClassification(t *testing.T) {
	a := NewAdapter(Config{}, nil)

	// Unsupported input forms: empty PURL, unversioned PURL, unsupported ecosystem, unsupported capability.
	badReqs := []adapter.EvaluationRequest{
		{Artifact: adapter.ArtifactInput{}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:generic/foo@1.0.0"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityLicenses}},
	}
	for i, req := range badReqs {
		_, err := a.Evaluate(context.Background(), req)
		var ae *adapter.AdapterError
		if !errors.As(err, &ae) || ae.Code != adapter.ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("case %d: expected non-retryable ErrUnsupportedInput, got %v", i, err)
		}
	}

	// Upstream HTTP 401, 429, 502, invalid JSON, missing ID, and timeout.
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode {
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
		case "429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "502":
			w.WriteHeader(http.StatusBadGateway)
		case "bad-json":
			_, _ = w.Write([]byte(`not-json`))
		case "missing-id":
			_, _ = w.Write([]byte(`{"vulns": [{"summary": "no id"}]}`))
		case "repeat-token":
			_, _ = w.Write([]byte(`{"vulns": [], "next_page_token": "same"}`))
		case "slow":
			time.Sleep(80 * time.Millisecond)
		}
	}))
	defer srv.Close()

	clientAdapter := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())
	validReq := adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	}

	expectCode := func(m string, want adapter.ErrorCode, wantRetry bool) {
		t.Helper()
		mode = m
		_, err := clientAdapter.Evaluate(context.Background(), validReq)
		var ae *adapter.AdapterError
		if !errors.As(err, &ae) || ae.Code != want || ae.Retryable != wantRetry {
			t.Fatalf("mode %s: got err=%+v, want code=%s retryable=%v", m, err, want, wantRetry)
		}
	}

	expectCode("401", adapter.ErrAuthFailed, false)
	expectCode("429", adapter.ErrRateLimited, true)
	expectCode("502", adapter.ErrUpstreamUnavailable, true)
	expectCode("bad-json", adapter.ErrMalformedResponse, false)
	expectCode("missing-id", adapter.ErrMalformedResponse, false)
	expectCode("repeat-token", adapter.ErrMalformedResponse, false)

	mode = "slow"
	tctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	_, err := clientAdapter.Evaluate(tctx, validReq)
	var ae *adapter.AdapterError
	if !errors.As(err, &ae) || ae.Code != adapter.ErrTimeout || !ae.Retryable {
		t.Fatalf("expected retryable ErrTimeout, got %v", err)
	}
}
