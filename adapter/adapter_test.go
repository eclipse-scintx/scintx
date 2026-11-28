// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestAdapterErrorFormattingAndUnwrap(t *testing.T) {
	cause := errors.New("socket reset by peer")
	err := &AdapterError{
		Code:      ErrUpstreamUnavailable,
		Message:   "failed to reach provider",
		Retryable: true,
		Cause:     cause,
	}

	want := "upstream_unavailable: failed to reach provider"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("expected errors.Is(err, cause) to be true")
	}

	var nilErr *AdapterError
	if nilErr.Error() != "" {
		t.Fatalf("nil AdapterError.Error() = %q, want empty", nilErr.Error())
	}
	if nilErr.Unwrap() != nil {
		t.Fatalf("nil AdapterError.Unwrap() = %v, want nil", nilErr.Unwrap())
	}
}

func TestAvailabilityAndErrorClassifiers(t *testing.T) {
	if _, ok := ValidateBaseURL("OSV", "https://api.osv.dev"); !ok {
		t.Fatal("expected valid https base URL")
	}
	for _, bad := range []string{"://bad", "ftp://api.osv.dev", "http://", ""} {
		if st, ok := ValidateBaseURL("OSV", bad); ok || st.State != StateUnconfigured || st.Reasons[0] != ReasonInvalidConfiguration {
			t.Fatalf("ValidateBaseURL(%q) = (%+v, %v), want unconfigured", bad, st, ok)
		}
	}

	if st := AvailabilityFromHTTPStatus("OSV", http.StatusOK); st.State != StateReady || !st.Available {
		t.Fatalf("expected StateReady on 200, got %+v", st)
	}
	for _, code := range []int{http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden} {
		if st := AvailabilityFromHTTPStatus("OSV", code); st.State != StateUnreachable || st.Available || st.Reasons[0] != ReasonAuthenticationFailed {
			t.Fatalf("HTTP %d: expected ReasonAuthenticationFailed, got %+v", code, st)
		}
	}
	if st := AvailabilityFromHTTPStatus("OSV", http.StatusTooManyRequests); st.State != StateDegraded || !st.Available || st.Reasons[0] != ReasonRateLimited {
		t.Fatalf("expected StateDegraded on 429, got %+v", st)
	}
	if st := AvailabilityFromHTTPStatus("OSV", http.StatusBadGateway); st.State != StateUnreachable || st.Reasons[0] != ReasonUpstreamUnreachable {
		t.Fatalf("expected ReasonUpstreamUnreachable on 502, got %+v", st)
	}

	// Verify ClassifyHTTPStatusError retryability across 401/402/403, 429, 400/404, and 5xx (#97).
	for _, tc := range []struct {
		status int
		code   ErrorCode
		retry  bool
	}{
		{http.StatusUnauthorized, ErrAuthFailed, false},
		{http.StatusPaymentRequired, ErrAuthFailed, false},
		{http.StatusForbidden, ErrAuthFailed, false},
		{http.StatusTooManyRequests, ErrRateLimited, true},
		{http.StatusBadRequest, ErrUpstreamUnavailable, false},
		{http.StatusNotFound, ErrUpstreamUnavailable, false},
		{http.StatusInternalServerError, ErrUpstreamUnavailable, true},
		{http.StatusBadGateway, ErrUpstreamUnavailable, true},
		{http.StatusServiceUnavailable, ErrUpstreamUnavailable, true},
	} {
		ae := ClassifyHTTPStatusError("OSV", "/v1/query", tc.status)
		if ae.Code != tc.code || ae.Retryable != tc.retry {
			t.Fatalf("HTTP %d: got (%s, retry=%v), want (%s, retry=%v)", tc.status, ae.Code, ae.Retryable, tc.code, tc.retry)
		}
	}

	// Verify ClassifyTransportError distinguishes timeouts from connection errors (#97).
	if ae := ClassifyTransportError("OSV", "/v1/query", context.DeadlineExceeded); ae.Code != ErrTimeout || !ae.Retryable {
		t.Fatalf("expected retryable ErrTimeout on DeadlineExceeded, got %+v", ae)
	}
	if ae := ClassifyTransportError("OSV", "/v1/query", timeoutNetError{}); ae.Code != ErrTimeout || !ae.Retryable {
		t.Fatalf("expected retryable ErrTimeout on net.Error timeout, got %+v", ae)
	}
	if ae := ClassifyTransportError("OSV", "/v1/query", errors.New("connection refused")); ae.Code != ErrUpstreamUnavailable || !ae.Retryable {
		t.Fatalf("expected retryable ErrUpstreamUnavailable on connection error, got %+v", ae)
	}

	capRep := NewCompletedCapabilityReport(CheckKnownVulnerabilities, nil)
	if capRep.Status != CapabilityStatusCompleted || capRep.Checks[CheckKnownVulnerabilities].Findings == nil {
		t.Fatalf("expected completed capability report with non-nil findings slice, got %+v", capRep)
	}
	desc := AdapterDescriptor{
		Slug: "osv", AdapterVersion: "0.1.0",
		Capabilities: map[Capability]CapabilityDescriptor{CapabilityVulnerabilities: {Checks: []Check{CheckKnownVulnerabilities}}},
	}
	errRep := NewErroredProviderReport(desc, "run-1", nil)
	if errRep.Capabilities[CapabilityVulnerabilities].Status != CapabilityStatusErrored ||
		errRep.Capabilities[CapabilityVulnerabilities].Checks[CheckKnownVulnerabilities].Error.Code != ErrUpstreamUnavailable {
		t.Fatalf("unexpected fallback errored report: %+v", errRep)
	}
}

func TestValidateVersionedPURL(t *testing.T) {
	supported := []Ecosystem{EcosystemNPM, EcosystemMaven, EcosystemGolang, EcosystemRPM, EcosystemVSCodeExtension}

	for _, valid := range []string{
		"pkg:npm/lodash@4.17.20",
		"pkg:rpm/fedora/openssl@3.0.8~rc1",
		"pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible",
	} {
		if _, _, err := ValidateVersionedPURL("test", valid, supported); err != nil {
			t.Fatalf("expected %q to be valid, got %v", valid, err)
		}
	}

	for _, invalid := range []string{
		"",
		"not-a-purl",
		"pkg:npm/lodash",
		"pkg:maven/commons-text@1.9",
		"pkg:rpm/openssl@3.0.8",
		"pkg:vscode-extension/trivy@1.8.12",
		"pkg:npm/lodash@^4.17.0",
		"pkg:npm/lodash@~4.17.0",
		"pkg:npm/lodash@>=4.0.0",
		"pkg:npm/lodash@%5B4.0.0%2C4.17.20%29",
		"pkg:npm/lodash@*",
		"pkg:generic/foo@1.0.0",
	} {
		_, _, err := ValidateVersionedPURL("test", invalid, supported)
		var ae *AdapterError
		if !errors.As(err, &ae) || ae.Code != ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("input %q: expected non-retryable ErrUnsupportedInput, got %v", invalid, err)
		}
	}
}
