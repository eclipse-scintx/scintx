// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import "time"

// CapabilityStatus indicates whether analysis for a capability completed or was partial (#68, #70, #72).
type CapabilityStatus string

const (
	CapabilityStatusCompleted   CapabilityStatus = "completed"
	CapabilityStatusPartial     CapabilityStatus = "partial"
	CapabilityStatusUnavailable CapabilityStatus = "unavailable"
)

// Severity represents the normalized severity level of a finding (#68, #70).
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// CheckResult records the status of a specific check within a capability (e.g., "malware") (#68, #70).
type CheckResult struct {
	ID     string           `json:"id"`
	Status CapabilityStatus `json:"status"`
}

// Finding represents an individual security issue or observation returned by a provider (#68, #70, #72).
type Finding struct {
	ID             string         `json:"id"`
	Type           string         `json:"type"`
	Severity       Severity       `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	Artifact       *ArtifactInput `json:"artifact,omitempty"`
	DependencyPath []string       `json:"dependencyPath,omitempty"`
	Identifiers    []string       `json:"identifiers,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// CapabilityReport holds the coverage status, checks, and findings for one capability (#68, #70, #72).
type CapabilityReport struct {
	Status   CapabilityStatus `json:"status"`
	Checks   []CheckResult    `json:"checks,omitempty"`
	Findings []Finding        `json:"findings"`
}

// ProviderReport is the normalized output of a single Provider Run (#68, #70).
type ProviderReport struct {
	SchemaVersion    string                          `json:"schemaVersion,omitempty"`
	ID               string                          `json:"id"`
	ProviderRunID    string                          `json:"providerRunId"`
	Provider         string                          `json:"provider"`
	AdapterVersion   string                          `json:"adapterVersion,omitempty"`
	Capabilities     map[Capability]CapabilityReport `json:"capabilities"`
	ProviderVerdict  *string                         `json:"providerVerdict"`
	ResponseMetadata map[string]any                  `json:"responseMetadata,omitempty"`
	RawEvidenceRef   string                          `json:"rawEvidenceRef,omitempty"`
}

// SubmissionRef identifies the submission inside an AggregateReport (#68).
type SubmissionRef struct {
	ID         string    `json:"id"`
	AcceptedAt time.Time `json:"acceptedAt"`
}

// GatewayConfigRef records the immutable gateway configuration revision used (#68, #73).
type GatewayConfigRef struct {
	Revision    string `json:"revision"`
	SnapshotRef string `json:"snapshotRef"`
}

// GatewayInfo records gateway identity and software version in an AggregateReport (#68).
type GatewayInfo struct {
	InstanceID    string           `json:"instanceId"`
	Version       string           `json:"version"`
	Configuration GatewayConfigRef `json:"configuration"`
}

// PolicySummary records the resolved policy and deadline in an AggregateReport (#68).
type PolicySummary struct {
	ID                   string       `json:"id"`
	Version              string       `json:"version"`
	Capabilities         []Capability `json:"capabilities"`
	EvaluationDeadlineMs int64        `json:"evaluationDeadlineMs"`
}

// ProviderSelection records availability, eligibility, and selection for one provider (#68, #71).
type ProviderSelection struct {
	Slug                string       `json:"slug"`
	AdapterVersion      string       `json:"adapterVersion"`
	Available           bool         `json:"available"`
	Eligible            bool         `json:"eligible"`
	Selected            bool         `json:"selected"`
	MatchedCapabilities []Capability `json:"matched_capabilities"`
	Reasons             []string     `json:"reasons"`
	ProviderRunID       string       `json:"providerRunId,omitempty"`
}

// ProviderRunStatus describes the execution state of an attempted ProviderRun (#68, #72, #74, #75).
type ProviderRunStatus string

const (
	RunStatusCompleted  ProviderRunStatus = "completed"
	RunStatusFailed     ProviderRunStatus = "failed"
	RunStatusTimedOut   ProviderRunStatus = "timed_out"
	RunStatusIncomplete ProviderRunStatus = "incomplete"
)

// ProviderRun tracks the execution lifecycle and errors of a selected provider (#68, #72, #75).
type ProviderRun struct {
	ID          string            `json:"id"`
	Provider    string            `json:"provider"`
	Status      ProviderRunStatus `json:"status"`
	StartedAt   time.Time         `json:"startedAt"`
	CompletedAt *time.Time        `json:"completedAt"`
	DurationMs  int64             `json:"durationMs"`
	ReportID    *string           `json:"reportId"`
	Error       *AdapterError     `json:"error,omitempty"`
}

// AggregateReport is the immutable snapshot of provider selection, execution, and evidence (#68).
// It serves as the sole input to the Policy Engine.
type AggregateReport struct {
	SchemaVersion   string              `json:"schemaVersion"`
	ID              string              `json:"id"`
	Submission      SubmissionRef       `json:"submission"`
	Artifact        ArtifactInput       `json:"artifact"`
	Gateway         GatewayInfo         `json:"gateway"`
	Policy          PolicySummary       `json:"policy"`
	Providers       []ProviderSelection `json:"providers"`
	ProviderRuns    []ProviderRun       `json:"providerRuns"`
	ProviderReports []ProviderReport    `json:"providerReports"`
}
