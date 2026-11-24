// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import "time"

// PolicyRule defines a single violation or annotation condition in a PolicyDefinition (#68).
type PolicyRule struct {
	Description string `yaml:"description" json:"description"`
	When        string `yaml:"when" json:"when"`
}

// PolicyProviders defines optional provider selection controls in a PolicyDefinition (#68, #71).
type PolicyProviders struct {
	Requested []string `yaml:"requested,omitempty" json:"requested,omitempty"`
	Allowlist []string `yaml:"allowlist,omitempty" json:"allowlist,omitempty"`
	Denylist  []string `yaml:"denylist,omitempty" json:"denylist,omitempty"`
}

// PolicyDefinition represents a source-controlled SCINTX policy file (#68).
type PolicyDefinition struct {
	SchemaVersion      string                `yaml:"schemaVersion" json:"schemaVersion"`
	ID                 string                `yaml:"id" json:"id"`
	Name               string                `yaml:"name" json:"name"`
	Version            string                `yaml:"version" json:"version"`
	Description        string                `yaml:"description" json:"description"`
	Capabilities       []Capability          `yaml:"capabilities" json:"capabilities"`
	Violations         map[string]PolicyRule `yaml:"violations" json:"violations"`
	Annotations        map[string]PolicyRule `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	EvaluationDeadline string                `yaml:"evaluationDeadline" json:"evaluationDeadline"`
	Providers          PolicyProviders       `yaml:"providers,omitempty" json:"providers,omitempty"`

	// ParsedDeadline stores the validated duration parsed from EvaluationDeadline.
	ParsedDeadline time.Duration `yaml:"-" json:"-"`
}

// PolicyVerdict is the conclusion produced by evaluating a Policy against an AggregateReport (#67, #68).
type PolicyVerdict string

const (
	VerdictSatisfied    PolicyVerdict = "satisfied"
	VerdictViolated     PolicyVerdict = "violated"
	VerdictUndetermined PolicyVerdict = "undetermined"
)

// EvaluationStatus indicates whether the Policy Engine finished evaluating the report (#68).
type EvaluationStatus string

const (
	EvaluationCompleted EvaluationStatus = "completed"
	EvaluationFailed    EvaluationStatus = "failed"
)

// EvidenceStatus summarizes whether all declared capabilities and selected runs completed (#68, #75).
type EvidenceStatus string

const (
	EvidenceComplete    EvidenceStatus = "complete"
	EvidencePartial     EvidenceStatus = "partial"
	EvidenceUnavailable EvidenceStatus = "unavailable"
)

// PolicyReportRef identifies the policy ID and version evaluated in a PolicyReport (#68).
type PolicyReportRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// RuleEvidence links a triggered rule match back to the specific Finding or ProviderRun (#68, #75).
type RuleEvidence struct {
	Type             string            `json:"type"`
	Capability       Capability        `json:"capability,omitempty"`
	Provider         string            `json:"provider"`
	ProviderRunID    string            `json:"providerRunId,omitempty"`
	ProviderReportID string            `json:"providerReportId,omitempty"`
	FindingID        string            `json:"findingId,omitempty"`
	Status           ProviderRunStatus `json:"status,omitempty"`
	ErrorCode        ErrorCode         `json:"errorCode,omitempty"`
}

// RuleMatch records an artifact and supporting evidence that triggered a policy rule (#68).
type RuleMatch struct {
	Artifact       ArtifactInput  `json:"artifact"`
	DependencyPath []string       `json:"dependencyPath,omitempty"`
	Evidence       []RuleEvidence `json:"evidence"`
}

// TriggeredRule represents a single violation or annotation triggered during policy evaluation (#67, #68).
// Open VSX maps $.violations[*].id and $.violations[*].description from this type (#67).
type TriggeredRule struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Matches     []RuleMatch `json:"matches"`
}

// PolicyReport is the output of the Policy Engine for a submission (#67, #68, #75).
type PolicyReport struct {
	SchemaVersion     string           `json:"schemaVersion,omitempty"`
	ID                string           `json:"id"`
	SubmissionID      string           `json:"submissionId"`
	AggregateReportID string           `json:"aggregateReportId"`
	Policy            PolicyReportRef  `json:"policy"`
	Artifact          ArtifactInput    `json:"artifact"`
	EvaluationStatus  EvaluationStatus `json:"evaluationStatus"`
	EvidenceStatus    EvidenceStatus   `json:"evidenceStatus"`
	PolicyVerdict     PolicyVerdict    `json:"policyVerdict"`
	UnresolvedRules   []string         `json:"unresolvedRules,omitempty"`
	Violations        []TriggeredRule  `json:"violations"`
	Annotations       []TriggeredRule  `json:"annotations"`
}
