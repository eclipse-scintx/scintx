// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import "errors"

// This file defines the normalized ProviderReport, CapabilityReport,
// CheckReport, Finding, FindingType, and provenance metadata keys returned by
// provider adapters (#68, #70, #72, #98).

// ProviderReport is the normalized output of a single Provider Run.
type ProviderReport struct {
	SchemaVersion    string                          `json:"schemaVersion"`
	ID               string                          `json:"id,omitempty"`
	ProviderRunID    string                          `json:"providerRunId"`
	Provider         string                          `json:"provider"`
	AdapterVersion   string                          `json:"adapterVersion"`
	Capabilities     map[Capability]CapabilityReport `json:"capabilities"`
	ProviderVerdict  *string                         `json:"providerVerdict"`
	ResponseMetadata map[string]any                  `json:"responseMetadata,omitempty"`
	RawEvidenceRef   string                          `json:"rawEvidenceRef,omitempty"`
}

// CapabilityStatus summarizes check evaluation coverage across a capability.
type CapabilityStatus string

const (
	CapabilityStatusCompleted    CapabilityStatus = "completed"
	CapabilityStatusPartial      CapabilityStatus = "partial"
	CapabilityStatusUndetermined CapabilityStatus = "undetermined"
	CapabilityStatusErrored      CapabilityStatus = "errored"
)

// CheckStatus indicates whether an individual check within a capability was
// evaluated during a Provider Run.
type CheckStatus string

const (
	CheckStatusEvaluated    CheckStatus = "evaluated"
	CheckStatusNotEvaluated CheckStatus = "not_evaluated"
	CheckStatusErrored      CheckStatus = "errored"
)

// CapabilityReport holds the roll-up coverage status and nested check reports
// for one requested capability.
type CapabilityReport struct {
	Status CapabilityStatus      `json:"status"`
	Checks map[Check]CheckReport `json:"checks"`
}

// CheckReport holds the evaluation status, optional error, and attributed
// findings for a single check within a capability.
type CheckReport struct {
	Status   CheckStatus   `json:"status"`
	Error    *AdapterError `json:"error,omitempty"`
	Findings []Finding     `json:"findings"`
}

// NewCompletedCapabilityReport builds a completed CapabilityReport for a single
// evaluated Check, guaranteeing a non-nil Findings slice (#72).
func NewCompletedCapabilityReport(check Check, findings []Finding) CapabilityReport {
	if findings == nil {
		findings = []Finding{}
	}
	return CapabilityReport{
		Status: CapabilityStatusCompleted,
		Checks: map[Check]CheckReport{
			check: {
				Status:   CheckStatusEvaluated,
				Findings: findings,
			},
		},
	}
}

// NewErroredProviderReport builds a normalized ProviderReport recording full
// provider provenance (providerRunId, provider slug, adapterVersion, and
// errored capability/check states) whenever an adapter run fails (#72, #74, #98).
func NewErroredProviderReport(desc AdapterDescriptor, providerRunID string, err error) ProviderReport {
	var ae *AdapterError
	if errors.As(err, &ae) && ae != nil {
		ae = &AdapterError{Code: ae.Code, Message: ae.Message, Retryable: ae.Retryable}
	} else {
		ae = &AdapterError{Code: ErrUpstreamUnavailable, Message: "provider execution failed"}
	}

	caps := make(map[Capability]CapabilityReport, len(desc.Capabilities))
	for capName, capDesc := range desc.Capabilities {
		checks := make(map[Check]CheckReport, len(capDesc.Checks))
		for _, chk := range capDesc.Checks {
			checks[chk] = CheckReport{
				Status:   CheckStatusErrored,
				Error:    ae,
				Findings: []Finding{},
			}
		}
		caps[capName] = CapabilityReport{
			Status: CapabilityStatusErrored,
			Checks: checks,
		}
	}

	return ProviderReport{
		SchemaVersion:  SchemaVersionV1,
		ID:             NewProviderReportID(desc.Slug, providerRunID),
		ProviderRunID:  providerRunID,
		Provider:       desc.Slug,
		AdapterVersion: desc.AdapterVersion,
		Capabilities:   caps,
	}
}

// NewProviderReportID returns a deterministic ProviderReport ID derived from
// providerRunID (or providerSlug when providerRunID is empty) (#68, #72, #98).
func NewProviderReportID(providerSlug, providerRunID string) string {
	if providerRunID != "" {
		return "report-" + providerRunID
	}
	return "report-" + providerSlug
}

// Severity represents the normalized severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// FindingType classifies a Finding within its capability (#70, #72).
type FindingType string

const (
	FindingTypeVulnerability FindingType = "vulnerability"
	FindingTypeMalware       FindingType = "malware"
	FindingTypeLicense       FindingType = "license"
	FindingTypeHealth        FindingType = "health"
	FindingTypeIntegrity     FindingType = "integrity"
	FindingTypeDependency    FindingType = "dependency"
)

// Standardized Finding.Metadata, ProviderReport.ResponseMetadata, and raw
// evidence keys shared across adapters (#98).
const (
	MetaKeySchemaVersion        = "schemaVersion"
	MetaKeyPublished            = "published"
	MetaKeyModified             = "modified"
	MetaKeyWithdrawn            = "withdrawn"
	MetaKeyAliases              = "aliases"
	MetaKeyRelated              = "related"
	MetaKeyUpstream             = "upstream"
	MetaKeySeverity             = "severity"
	MetaKeyAffected             = "affected"
	MetaKeyReferences           = "references"
	MetaKeyDatabaseSpecific     = "databaseSpecific"
	MetaKeyDisplayName          = "displayName"
	MetaKeyCVE                  = "cve"
	MetaKeyCWE                  = "cwe"
	MetaKeyCVSSScore            = "cvssScore"
	MetaKeyCVSSVector           = "cvssVector"
	MetaKeyVersionRanges        = "versionRanges"
	MetaKeyComponentCoordinates = "componentCoordinates"
	MetaKeyComponentReference   = "componentReference"
	MetaKeyComponentDescription = "componentDescription"

	RespMetaKeyEndpoint            = "endpoint"
	RespMetaKeyQueryPURL           = "queryPurl"
	RespMetaKeyQueriedCoordinate   = "queriedCoordinate"
	RespMetaKeyFallbackEcosystem   = "fallbackEcosystem"
	RespMetaKeyFallbackPackageName = "fallbackPackageName"
	RespMetaKeyPageCount           = "pageCount"
	RespMetaKeyHydratedRecordCount = "hydratedRecordCount"
	RespMetaKeyComponentCount      = "componentCount"

	EvidenceKeyPages           = "pages"
	EvidenceKeyCount           = "count"
	EvidenceKeyHydratedRecords = "hydratedRecords"
	EvidenceKeyComponents      = "components"
)

// Finding represents an individual security issue or observation returned by a provider.
type Finding struct {
	ID          string         `json:"id"`
	Type        FindingType    `json:"type"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Artifact    *ArtifactInput `json:"artifact,omitempty"`
	Identifiers []string       `json:"identifiers,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}
