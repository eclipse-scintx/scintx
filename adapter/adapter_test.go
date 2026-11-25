// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"errors"
	"net/http"
	"testing"
)

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

func TestAvailabilityConstructorsAndReportHelpers(t *testing.T) {
	if _, ok := ValidateBaseURL("OSV", "https://api.osv.dev"); !ok {
		t.Fatal("expected valid base URL")
	}
	if st, ok := ValidateBaseURL("OSV", "://bad"); ok || st.State != StateUnconfigured || st.Reasons[0] != ReasonInvalidConfiguration {
		t.Fatalf("expected unconfigured status on bad URL, got %+v", st)
	}

	if st := AvailabilityFromHTTPStatus("OSV", http.StatusOK); st.State != StateReady || !st.Available {
		t.Fatalf("expected StateReady on 200, got %+v", st)
	}
	if st := AvailabilityFromHTTPStatus("OSV", http.StatusUnauthorized); st.State != StateUnreachable || st.Reasons[0] != ReasonAuthenticationFailed {
		t.Fatalf("expected ReasonAuthenticationFailed on 401, got %+v", st)
	}
	if st := AvailabilityFromHTTPStatus("OSV", http.StatusTooManyRequests); st.State != StateDegraded || !st.Available || st.Reasons[0] != ReasonRateLimited {
		t.Fatalf("expected StateDegraded on 429, got %+v", st)
	}
	if st := AvailabilityFromHTTPStatus("OSV", http.StatusBadGateway); st.State != StateUnreachable || st.Reasons[0] != ReasonUpstreamUnreachable {
		t.Fatalf("expected ReasonUpstreamUnreachable on 502, got %+v", st)
	}

	capRep := NewCompletedCapabilityReport(CheckKnownVulnerabilities, nil)
	if capRep.Status != CapabilityStatusCompleted || capRep.Checks[CheckKnownVulnerabilities].Findings == nil {
		t.Fatalf("expected completed capability report with non-nil findings slice, got %+v", capRep)
	}
}
