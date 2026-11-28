// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/adapter"
)

func TestEmptyResultCapabilityFilteringAndSeverity(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	a := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())

	// 1. Verify empty results across {}, {"vulns":[]}, and {"vulns":null}, and selective capability filtering (#97).
	for _, emptyPayload := range []string{`{}`, `{"vulns": []}`, `{"vulns": null}`} {
		body = emptyPayload
		res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
			Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
			RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities, adapter.CapabilityThreats},
		})
		if err != nil || len(res.Report.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities].Findings) != 0 ||
			len(res.Report.Capabilities[adapter.CapabilityThreats].Checks[adapter.CheckMalware].Findings) != 0 {
			t.Fatalf("payload %s: expected evaluated empty findings slices, got %+v err=%v", emptyPayload, res, err)
		}
	}
	body = `{"vulns":[{"id":"GHSA-1111-2222-3333","summary":"vuln"},{"id":"MAL-2026-0001","summary":"malware"}]}`
	for _, capOnly := range []adapter.Capability{adapter.CapabilityVulnerabilities, adapter.CapabilityThreats} {
		res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
			Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{capOnly},
		})
		if err != nil || len(res.Report.Capabilities) != 1 || res.Report.Capabilities[capOnly].Status != adapter.CapabilityStatusCompleted {
			t.Fatalf("cap %s: unexpected selective report %+v err=%v", capOnly, res, err)
		}
	}

	// 3. Verify severity fallbacks across ecosystem_specific, numeric CVSS, CVSS vectors, and unknown.
	for _, tc := range []struct {
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
		{Vulnerability{ID: "DEBIAN-1", Severity: []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}, adapter.SeverityCritical},
		{Vulnerability{ID: "GHSA-V4", Severity: []SeverityEntry{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N"}}}, adapter.SeverityMedium},
		{Vulnerability{ID: "UBUNTU-1", Affected: []AffectedEntry{{EcosystemSpecific: map[string]any{"urgency": "unimportant"}}}}, adapter.SeverityInfo},
		{Vulnerability{ID: "OSV-9"}, adapter.SeverityUnknown},
	} {
		if got := extractSeverity(tc.v); got != tc.want {
			t.Errorf("extractSeverity(%s) = %q, want %q", tc.v.ID, got, tc.want)
		}
	}
}

func TestCheckAvailabilityStates(t *testing.T) {
	if st := NewAdapter(Config{BaseURL: "://bad"}, nil).CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Available || st.Reasons[0] != adapter.ReasonInvalidConfiguration {
		t.Fatalf("expected invalid_configuration, got %+v", st)
	}
	if st := NewAdapter(Config{BaseURL: "https://mirror.example.com", RequireAuth: true}, nil).CheckAvailability(context.Background()); st.State != adapter.StateUnconfigured || st.Reasons[0] != adapter.ReasonMissingCredentials {
		t.Fatalf("expected missing_credentials, got %+v", st)
	}

	var statusCode int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(statusCode) }))
	a := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())

	for _, tc := range []struct {
		code   int
		state  adapter.AvailabilityState
		avail  bool
		reason adapter.ReasonCode
	}{
		{http.StatusOK, adapter.StateReady, true, ""},
		{http.StatusTooManyRequests, adapter.StateDegraded, true, adapter.ReasonRateLimited},
		{http.StatusUnauthorized, adapter.StateUnreachable, false, adapter.ReasonAuthenticationFailed},
		{http.StatusForbidden, adapter.StateUnreachable, false, adapter.ReasonAuthenticationFailed},
		{http.StatusServiceUnavailable, adapter.StateUnreachable, false, adapter.ReasonUpstreamUnreachable},
	} {
		statusCode = tc.code
		if st := a.CheckAvailability(context.Background()); st.State != tc.state || st.Available != tc.avail || (tc.reason != "" && st.Reasons[0] != tc.reason) {
			t.Fatalf("HTTP %d: got %+v, want state=%s avail=%v reason=%s", tc.code, st, tc.state, tc.avail, tc.reason)
		}
	}
	srv.Close()
	if st := a.CheckAvailability(context.Background()); st.State != adapter.StateUnreachable || st.Available || st.Reasons[0] != adapter.ReasonUpstreamUnreachable {
		t.Fatalf("expected unreachable on closed server, got %+v", st)
	}
}

func TestEvaluateErrorClassification(t *testing.T) {
	validReq := adapter.EvaluationRequest{
		Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	}

	// 1. Missing required mirror credentials and invalid BaseURL fail closed without network calls (#97).
	var ae *adapter.AdapterError
	if _, err := NewAdapter(Config{RequireAuth: true}, nil).Evaluate(context.Background(), validReq); !errors.As(err, &ae) || ae.Code != adapter.ErrAuthFailed || ae.Retryable {
		t.Fatalf("expected non-retryable ErrAuthFailed when RequireAuth token is missing, got %v", err)
	}
	if _, err := NewAdapter(Config{BaseURL: "://bad"}, nil).Evaluate(context.Background(), validReq); !errors.As(err, &ae) || ae.Code != adapter.ErrUpstreamUnavailable || ae.Retryable {
		t.Fatalf("expected non-retryable ErrUpstreamUnavailable on invalid BaseURL, got %v", err)
	}

	// 2. Unsupported inputs: empty, digest-only, content-only, unversioned, missing namespace, range, unsupported ecosystem/capability (#97).
	a := NewAdapter(Config{}, nil)
	vulnCaps := []adapter.Capability{adapter.CapabilityVulnerabilities}
	for _, badPURL := range []string{"", "pkg:npm/lodash", "pkg:maven/commons-text@1.9", "pkg:vscode-extension/trivy@1.8.12", "pkg:npm/lodash@^4.17.0", "pkg:generic/foo@1.0.0"} {
		if _, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{Artifact: adapter.ArtifactInput{PURL: badPURL}, RequestedCapabilities: vulnCaps}); !errors.As(err, &ae) || ae.Code != adapter.ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("purl %q: expected non-retryable ErrUnsupportedInput, got %v", badPURL, err)
		}
	}
	for i, req := range []adapter.EvaluationRequest{
		{Artifact: adapter.ArtifactInput{Digest: &adapter.Digest{Algorithm: "sha256", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}, RequestedCapabilities: vulnCaps},
		{Artifact: adapter.ArtifactInput{ContentMeta: &adapter.ContentMetadata{Filename: "app.tar.gz"}}, RequestedCapabilities: vulnCaps},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: []adapter.Capability{adapter.CapabilityLicenses}},
		{Artifact: adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, RequestedCapabilities: nil},
	} {
		if _, err := a.Evaluate(context.Background(), req); !errors.As(err, &ae) || ae.Code != adapter.ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("case %d: expected non-retryable ErrUnsupportedInput, got %v", i, err)
		}
	}

	// 3. Upstream HTTP 401/403/429/400/502, malformed responses, stub hydration errors, pagination cap, and timeout (#97).
	var qStatus, hStatus, pageSeq int
	var qBody, hBody string
	var slow bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow {
			time.Sleep(80 * time.Millisecond)
			return
		}
		if r.URL.Path != queryEndpoint {
			w.WriteHeader(hStatus)
			_, _ = w.Write([]byte(hBody))
			return
		}
		if pageSeq > 0 {
			pageSeq++
			_, _ = fmt.Fprintf(w, `{"vulns":[],"next_page_token":"tok-%d"}`, pageSeq)
			return
		}
		w.WriteHeader(qStatus)
		_, _ = w.Write([]byte(qBody))
	}))
	clientAdapter := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())

	stubJSON := `{"vulns":[{"id":"GHSA-stub","modified":"2026-01-01T00:00:00Z"}]}`
	for i, tc := range []struct {
		qStatus, hStatus, pages int
		qBody, hBody            string
		want                    adapter.ErrorCode
		retry                   bool
	}{
		{http.StatusUnauthorized, 200, 0, "", "", adapter.ErrAuthFailed, false},
		{http.StatusForbidden, 200, 0, "", "", adapter.ErrAuthFailed, false},
		{http.StatusTooManyRequests, 200, 0, "", "", adapter.ErrRateLimited, true},
		{http.StatusBadRequest, 200, 0, "", "", adapter.ErrUpstreamUnavailable, false},
		{http.StatusBadGateway, 200, 0, "", "", adapter.ErrUpstreamUnavailable, true},
		{200, 200, 0, `not-json`, "", adapter.ErrMalformedResponse, false},
		{200, 200, 0, `{"vulns":[{"summary":"no id"}]}`, "", adapter.ErrMalformedResponse, false},
		{200, 200, 0, `{"vulns":[],"next_page_token":"same"}`, "", adapter.ErrMalformedResponse, false},
		{200, 200, 1, "", "", adapter.ErrMalformedResponse, false},
		{200, 200, 0, stubJSON, `not-json`, adapter.ErrMalformedResponse, false},
		{200, 200, 0, stubJSON, `{"summary":"missing id"}`, adapter.ErrMalformedResponse, false},
		{200, http.StatusTooManyRequests, 0, stubJSON, "", adapter.ErrRateLimited, true},
	} {
		qStatus, hStatus, pageSeq, qBody, hBody = tc.qStatus, tc.hStatus, tc.pages, tc.qBody, tc.hBody
		if _, err := clientAdapter.Evaluate(context.Background(), validReq); !errors.As(err, &ae) || ae.Code != tc.want || ae.Retryable != tc.retry {
			t.Fatalf("case %d: got err=%+v, want code=%s retryable=%v", i, err, tc.want, tc.retry)
		}
	}

	slow, pageSeq = true, 0
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
