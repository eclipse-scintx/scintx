// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This file defines shared availability states, standardized selection and
// exclusion reason codes (#71, #73, #74), and shared HTTP status and transport
// error classifiers used across provider adapters.

// AvailabilityState describes the operational readiness of a provider adapter.
type AvailabilityState string

const (
	StateReady        AvailabilityState = "ready"
	StateDegraded     AvailabilityState = "degraded"
	StateUnconfigured AvailabilityState = "unconfigured"
	StateUnreachable  AvailabilityState = "unreachable"
)

// ReasonCode is a machine-readable reason explaining why a provider adapter is
// unconfigured, degraded, unreachable, or excluded from selection (#71, #73).
type ReasonCode string

const (
	ReasonInvalidConfiguration  ReasonCode = "invalid_configuration"
	ReasonMissingCredentials    ReasonCode = "missing_credentials"
	ReasonUpstreamUnreachable   ReasonCode = "upstream_unreachable"
	ReasonAuthenticationFailed  ReasonCode = "authentication_failed"
	ReasonRateLimited           ReasonCode = "rate_limited"
	ReasonProviderNotRegistered ReasonCode = "provider_not_registered"
	ReasonDisabledByGateway     ReasonCode = "disabled_by_gateway"
	ReasonIncompatibleSchema    ReasonCode = "incompatible_adapter_schema"
	ReasonCapabilityUnsupported ReasonCode = "capability_not_supported"
	ReasonUnsupportedInput      ReasonCode = "unsupported_artifact_input"
	ReasonUnsupportedEcosystem  ReasonCode = "unsupported_ecosystem"
	ReasonUnsupportedDigest     ReasonCode = "unsupported_digest_algorithm"
	ReasonArtifactSizeExceeded  ReasonCode = "artifact_size_exceeded"
	ReasonExcludedByAllowlist   ReasonCode = "excluded_by_policy_allowlist"
	ReasonExcludedByDenylist    ReasonCode = "excluded_by_policy_denylist"
)

// AvailabilityStatus reports whether an adapter is ready to run and why.
type AvailabilityStatus struct {
	State     AvailabilityState `json:"state"`
	Available bool              `json:"available"`
	Reasons   []ReasonCode      `json:"reasons,omitempty"`
	Message   string            `json:"message,omitempty"`
	CheckedAt time.Time         `json:"checkedAt"`
}

// NewReadyStatus constructs a healthy AvailabilityStatus in StateReady.
func NewReadyStatus() AvailabilityStatus {
	return AvailabilityStatus{
		State:     StateReady,
		Available: true,
		CheckedAt: time.Now().UTC(),
	}
}

// NewDegradedStatus constructs an AvailabilityStatus in StateDegraded that
// remains available for execution while recording a degradation reason.
func NewDegradedStatus(reason ReasonCode, message string) AvailabilityStatus {
	return AvailabilityStatus{
		State:     StateDegraded,
		Available: true,
		Reasons:   []ReasonCode{reason},
		Message:   message,
		CheckedAt: time.Now().UTC(),
	}
}

// NewUnconfiguredStatus constructs an unavailable status in StateUnconfigured.
func NewUnconfiguredStatus(reason ReasonCode, message string) AvailabilityStatus {
	return AvailabilityStatus{
		State:     StateUnconfigured,
		Available: false,
		Reasons:   []ReasonCode{reason},
		Message:   message,
		CheckedAt: time.Now().UTC(),
	}
}

// NewUnreachableStatus constructs an unavailable status in StateUnreachable.
func NewUnreachableStatus(reason ReasonCode, message string) AvailabilityStatus {
	return AvailabilityStatus{
		State:     StateUnreachable,
		Available: false,
		Reasons:   []ReasonCode{reason},
		Message:   message,
		CheckedAt: time.Now().UTC(),
	}
}

// ValidateBaseURL checks that rawURL is a valid http or https base URL with a
// non-empty host. If invalid, it returns a ready-to-use StateUnconfigured status.
func ValidateBaseURL(providerName, rawURL string) (AvailabilityStatus, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return NewUnconfiguredStatus(
			ReasonInvalidConfiguration,
			fmt.Sprintf("invalid %s base URL %q", providerName, rawURL),
		), false
	}
	return AvailabilityStatus{}, true
}

// AvailabilityFromHTTPStatus maps the HTTP status code of an upstream
// availability probe to a standardized AvailabilityStatus (#70, #74).
func AvailabilityFromHTTPStatus(providerName string, statusCode int) AvailabilityStatus {
	switch statusCode {
	case http.StatusOK:
		return NewReadyStatus()
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		return NewUnreachableStatus(
			ReasonAuthenticationFailed,
			fmt.Sprintf("%s API rejected credentials with HTTP %d", providerName, statusCode),
		)
	case http.StatusTooManyRequests:
		return NewDegradedStatus(
			ReasonRateLimited,
			fmt.Sprintf("%s API is reachable but currently rate-limited (HTTP 429)", providerName),
		)
	default:
		return NewUnreachableStatus(
			ReasonUpstreamUnreachable,
			fmt.Sprintf("%s API returned unexpected HTTP %d", providerName, statusCode),
		)
	}
}

// ClassifyTransportError maps context deadlines and net.Error timeouts to
// ErrTimeout and other network failures to ErrUpstreamUnavailable (#74).
func ClassifyTransportError(providerName, endpoint string, err error) *AdapterError {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &AdapterError{
			Code:      ErrTimeout,
			Message:   fmt.Sprintf("%s request to %s timed out", providerName, endpoint),
			Retryable: true,
			Cause:     err,
		}
	}
	return &AdapterError{
		Code:      ErrUpstreamUnavailable,
		Message:   fmt.Sprintf("failed to reach %s %s endpoint", providerName, endpoint),
		Retryable: true,
		Cause:     err,
	}
}

// ClassifyHTTPStatusError maps a non-200 upstream HTTP response code during
// Evaluate to a structured *AdapterError (#74).
func ClassifyHTTPStatusError(providerName, endpoint string, statusCode int) *AdapterError {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		return &AdapterError{
			Code:    ErrAuthFailed,
			Message: fmt.Sprintf("%s authentication failed with HTTP %d", providerName, statusCode),
		}
	case http.StatusTooManyRequests:
		return &AdapterError{
			Code:      ErrRateLimited,
			Message:   fmt.Sprintf("%s API rate limit exceeded (HTTP 429)", providerName),
			Retryable: true,
		}
	default:
		return &AdapterError{
			Code:      ErrUpstreamUnavailable,
			Message:   fmt.Sprintf("%s %s returned HTTP %d", providerName, endpoint, statusCode),
			Retryable: statusCode >= http.StatusInternalServerError,
		}
	}
}
