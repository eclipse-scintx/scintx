// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"context"
	"time"
)

// ProviderAdapter is the interface every SCINTX security provider integration implements (#70).
// Adapters declare their supported inputs and capabilities, verify availability, and
// translate upstream provider responses into normalized ProviderReport objects.
type ProviderAdapter interface {
	// Descriptor returns static metadata about the adapter, its schema version,
	// supported artifact inputs, and advertised capabilities.
	Descriptor() AdapterDescriptor

	// CheckAvailability verifies adapter configuration, credentials, and upstream readiness.
	// The gateway uses this status to populate provider availability and exclusion reasons
	// in the Aggregate Report (#70, #71, #73).
	CheckAvailability(ctx context.Context) AvailabilityStatus

	// Evaluate queries the upstream provider for the requested capabilities and
	// returns a normalized ProviderReport.
	// If the upstream call fails or returns an unparseable payload, Evaluate must
	// return an AdapterError rather than an empty completed report (#70, #72, #74).
	Evaluate(ctx context.Context, req EvaluationRequest) (*EvaluationResult, error)
}

// AdapterDescriptor declares what an adapter supports for gateway orchestration (#69, #70, #71).
type AdapterDescriptor struct {
	// Slug is the stable identifier used in policies and reports (e.g., "osv", "ossindex").
	Slug string `json:"slug"`

	// AdapterVersion is the semantic version of this adapter implementation.
	AdapterVersion string `json:"adapterVersion"`

	// SupportedSchemaVersion is the Provider Report schema version emitted by this adapter.
	SupportedSchemaVersion string `json:"supportedSchemaVersion"`

	// SupportedInputs declares which artifact forms, ecosystems, and digests the adapter accepts.
	SupportedInputs SupportedInputs `json:"supportedInputs"`

	// Capabilities lists the SCINTX capabilities this adapter can produce.
	Capabilities []Capability `json:"capabilities"`
}

// SupportedInputs defines the artifact input constraints for an adapter (#70, #71).
type SupportedInputs struct {
	// Types lists accepted input modes: "purl", "digest", and/or "content".
	Types []ArtifactInputType `json:"types"`

	// Ecosystems lists supported PURL ecosystems (e.g., "npm", "maven", "pypi", "vscode-extension").
	// An empty list when "purl" is supported means all ecosystems are accepted.
	Ecosystems []string `json:"ecosystems,omitempty"`

	// DigestAlgorithms lists supported hash algorithms when "digest" is supported (e.g., "sha256").
	DigestAlgorithms []string `json:"digestAlgorithms,omitempty"`

	// MaxContentBytes is the maximum artifact byte size accepted when "content" is supported.
	MaxContentBytes int64 `json:"maxContentBytes,omitempty"`
}

// AvailabilityState describes the operational readiness of a provider adapter (#70).
type AvailabilityState string

const (
	// StateReady means configuration, credentials, and upstream connectivity are healthy.
	StateReady AvailabilityState = "ready"

	// StateDegraded means the adapter can run but is experiencing throttling or partial issues.
	StateDegraded AvailabilityState = "degraded"

	// StateUnconfigured means required credentials or settings are missing or invalid.
	StateUnconfigured AvailabilityState = "unconfigured"

	// StateUnreachable means the upstream provider API could not be reached or rejected auth.
	StateUnreachable AvailabilityState = "unreachable"
)

// AvailabilityStatus reports whether a registered adapter is ready to execute and why (#70, #73).
type AvailabilityStatus struct {
	// State is the operational readiness state ("ready", "degraded", "unconfigured", "unreachable").
	State AvailabilityState `json:"state"`

	// Available is true when State is "ready" or "degraded" (maps to aggregateReport.providers[].available).
	Available bool `json:"available"`

	// Reasons contains machine-readable codes when unavailable or degraded
	// (e.g., "missing_credentials", "invalid_configuration", "rate_limited", "upstream_unreachable").
	Reasons []string `json:"reasons,omitempty"`

	// Message provides human-readable diagnostic detail for gateway operators.
	Message string `json:"message,omitempty"`

	// CheckedAt records when the availability check was performed.
	CheckedAt time.Time `json:"checkedAt"`
}

// EvaluationRequest contains the validated artifact and execution context for one Provider Run (#70).
type EvaluationRequest struct {
	// SubmissionID identifies the parent consumer submission.
	SubmissionID string `json:"submissionId"`

	// ProviderRunID identifies this specific provider execution in the Aggregate Report.
	ProviderRunID string `json:"providerRunId"`

	// Artifact holds the primary identifier, digest, or byte stream submitted by the consumer.
	Artifact ArtifactInput `json:"artifact"`

	// Components lists additional packages discovered in the artifact (such as dependencies)
	// so the adapter can batch-query them in a single Provider Run when supported.
	Components []ArtifactInput `json:"components,omitempty"`

	// RequestedCapabilities is the subset of adapter capabilities requested by the active policy.
	RequestedCapabilities []Capability `json:"requestedCapabilities"`
}

// EvaluationResult wraps the normalized ProviderReport and optional raw upstream evidence (#70).
type EvaluationResult struct {
	// Report is the normalized Provider Report included in the Aggregate Report.
	Report ProviderReport

	// RawEvidence holds the unmodified upstream payload for provenance storage.
	RawEvidence []byte
}

// ErrorCode classifies adapter execution failures for status tracking and policy evaluation (#70, #74).
type ErrorCode string

const (
	ErrUnsupportedInput    ErrorCode = "unsupported_artifact_input"
	ErrAuthFailed          ErrorCode = "authentication_failed"
	ErrRateLimited         ErrorCode = "rate_limited"
	ErrTimeout             ErrorCode = "provider_timeout"
	ErrUpstreamUnavailable ErrorCode = "upstream_unavailable"
	ErrMalformedResponse   ErrorCode = "malformed_provider_response"
)

// AdapterError represents a structured failure during provider execution (#70, #72, #74).
type AdapterError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
	Cause     error     `json:"-"`
}

func (e *AdapterError) Error() string {
	return string(e.Code) + ": " + e.Message
}

func (e *AdapterError) Unwrap() error {
	return e.Cause
}
