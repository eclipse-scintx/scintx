// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package adapter defines the Eclipse SCINTX provider adapter interface,
// capability and check identifiers, availability status, and error classification.
//
// Every supply-chain security provider integration implements ProviderAdapter.
// Adapters translate an upstream provider's native API into a normalized
// ProviderReport without performing cross-provider orchestration or policy
// evaluation.
package adapter

import (
	"context"

	"github.com/eclipse-scintx/scintx/api"
)

// SchemaVersionV1 is version 1 of the SCINTX Provider Report schema.
// It reuses api.SchemaVersionV1 so the gateway and adapters share one constant.
const SchemaVersionV1 = api.SchemaVersionV1

// ArtifactInput, Digest, and ContentMetadata reuse the validated domain types
// from package api so the gateway can pass submissions to adapters without
// copying or converting fields.
type (
	ArtifactInput   = api.ArtifactInput
	Digest          = api.Digest
	ContentMetadata = api.ContentMetadata
)

// Capability names a broad SCINTX security analysis category (#68, #71).
// Policies declare capabilities at the top level to select compatible adapters.
type Capability string

const (
	CapabilityVulnerabilities Capability = "vulnerabilities"
	CapabilityThreats         Capability = "threats"
	CapabilityLicenses        Capability = "licenses"
	CapabilityHealth          Capability = "health"
	CapabilityIntegrity       Capability = "integrity"
	CapabilityDependencies    Capability = "dependencies"
)

// Check identifies a specific analysis check within a Capability (#70, #71).
type Check string

const (
	// Checks under CapabilityVulnerabilities.
	CheckKnownVulnerabilities Check = "known-vulnerabilities"
	CheckExploitability       Check = "exploitability"
	CheckReachability         Check = "reachability"

	// Checks under CapabilityThreats.
	CheckMalware        Check = "malware"
	CheckTyposquatting  Check = "typosquatting"
	CheckInstallScripts Check = "install-scripts"
	CheckObfuscation    Check = "obfuscation"

	// Checks under CapabilityLicenses.
	CheckLicenseDetection     Check = "license-detection"
	CheckLicenseCompatibility Check = "license-compatibility"

	// Checks under CapabilityHealth.
	CheckMaintainerActivity Check = "maintainer-activity"
	CheckScorecard          Check = "scorecard"
	CheckAbandonment        Check = "abandonment"

	// Checks under CapabilityIntegrity.
	CheckSignatureVerification Check = "signature-verification"
	CheckSLSAProvenance        Check = "slsa-provenance"
	CheckChecksumMatch         Check = "checksum-match"

	// Checks under CapabilityDependencies.
	CheckDependencyGraph Check = "dependency-graph"
	CheckSBOMExtraction  Check = "sbom-extraction"
)

// ArtifactInputType identifies how an artifact was supplied to the gateway.
type ArtifactInputType string

const (
	InputTypePURL    ArtifactInputType = "purl"
	InputTypeDigest  ArtifactInputType = "digest"
	InputTypeContent ArtifactInputType = "content"
)

// ProviderAdapter is the contract implemented by every SCINTX provider adapter.
type ProviderAdapter interface {
	// Descriptor returns static metadata about the adapter, its supported
	// artifact inputs, and the capabilities and checks it implements.
	Descriptor() AdapterDescriptor

	// CheckAvailability verifies adapter settings, credentials, and upstream
	// reachability. The gateway uses this result to populate provider
	// availability and exclusion reasons in the Aggregate Report.
	CheckAvailability(ctx context.Context) AvailabilityStatus

	// Evaluate queries the upstream provider for the requested capabilities and
	// returns a normalized ProviderReport together with the raw upstream payload.
	// If the upstream call fails or returns an invalid payload, Evaluate must
	// return an *AdapterError rather than an empty completed report.
	Evaluate(ctx context.Context, req EvaluationRequest) (*EvaluationResult, error)
}

// AdapterDescriptor declares static adapter identity, input support, and capabilities.
type AdapterDescriptor struct {
	Slug                   string                              `json:"slug"`
	AdapterVersion         string                              `json:"adapterVersion"`
	SupportedSchemaVersion string                              `json:"supportedSchemaVersion"`
	SupportedInputs        SupportedInputs                     `json:"supportedInputs"`
	Capabilities           map[Capability]CapabilityDescriptor `json:"capabilities"`
}

// CapabilityDescriptor lists the specific checks an adapter implements under a capability.
type CapabilityDescriptor struct {
	Checks []Check `json:"checks"`
}

// SupportedInputs defines the artifact input forms accepted by an adapter.
type SupportedInputs struct {
	Types            []ArtifactInputType `json:"types"`
	Ecosystems       []Ecosystem         `json:"ecosystems,omitempty"`
	DigestAlgorithms []DigestAlgorithm   `json:"digestAlgorithms,omitempty"`
	MaxContentBytes  int64               `json:"maxContentBytes,omitempty"`
}

// EvaluationRequest holds the validated artifact and context for one Provider Run.
type EvaluationRequest struct {
	SubmissionID          string        `json:"submissionId"`
	ProviderRunID         string        `json:"providerRunId"`
	Artifact              ArtifactInput `json:"artifact"`
	RequestedCapabilities []Capability  `json:"requestedCapabilities"`
}

// EvaluationResult pairs the normalized ProviderReport with raw upstream bytes.
type EvaluationResult struct {
	Report              ProviderReport
	RawProviderResponse []byte
}

// ErrorCode classifies adapter execution failures for status tracking and policy rules.
type ErrorCode string

const (
	ErrUnsupportedInput    ErrorCode = "unsupported_artifact_input"
	ErrAuthFailed          ErrorCode = "authentication_failed"
	ErrRateLimited         ErrorCode = "rate_limited"
	ErrTimeout             ErrorCode = "provider_timeout"
	ErrUpstreamUnavailable ErrorCode = "upstream_unavailable"
	ErrMalformedResponse   ErrorCode = "malformed_provider_response"
)

// AdapterError represents a structured failure during provider execution.
type AdapterError struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
	Cause     error     `json:"-"`
}

// Error returns a concise code-prefixed message.
func (e *AdapterError) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code) + ": " + e.Message
}

// Unwrap returns the underlying cause so callers can inspect it with errors.Is.
func (e *AdapterError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
