// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file maps OSV records into normalized SCINTX Findings while preserving
// identifiers, relationships, affected package context, and provider provenance
// (#94, #98).

// normalizeFinding converts a full OSV Vulnerability record into a normalized
// SCINTX adapter.Finding for the submitted artifact PURL.
func normalizeFinding(v Vulnerability, artifactPURL string, isMalware bool) adapter.Finding {
	findingType := adapter.FindingTypeVulnerability
	if isMalware {
		findingType = adapter.FindingTypeMalware
	}
	title := strings.TrimSpace(v.Summary)
	if title == "" {
		title = v.ID
	}
	return adapter.Finding{
		ID:          v.ID,
		Type:        findingType,
		Severity:    extractSeverity(v),
		Title:       title,
		Description: v.Details,
		Artifact:    &adapter.ArtifactInput{PURL: artifactPURL},
		Identifiers: collectIdentifiers(v),
		Metadata:    buildFindingMetadata(v),
	}
}

// collectIdentifiers returns a deduplicated list of advisory identifiers
// starting with the primary OSV ID followed by aliases and upstream IDs.
func collectIdentifiers(v Vulnerability) []string {
	ids := append([]string{v.ID}, v.Aliases...)
	ids = append(ids, v.Upstream...)
	return adapter.DeduplicateStrings(ids...)
}

// buildFindingMetadata preserves OSV relationships, timestamps, severity
// vectors, affected package entries, references, and database_specific fields
// using the shared adapter.MetaKey* constants (#98).
func buildFindingMetadata(v Vulnerability) map[string]any {
	meta := make(map[string]any)
	if v.SchemaVersion != "" {
		meta[adapter.MetaKeySchemaVersion] = v.SchemaVersion
	}
	if v.Published != "" {
		meta[adapter.MetaKeyPublished] = v.Published
	}
	if v.Modified != "" {
		meta[adapter.MetaKeyModified] = v.Modified
	}
	if v.Withdrawn != "" {
		meta[adapter.MetaKeyWithdrawn] = v.Withdrawn
	}
	if len(v.Aliases) > 0 {
		meta[adapter.MetaKeyAliases] = v.Aliases
	}
	if len(v.Related) > 0 {
		meta[adapter.MetaKeyRelated] = v.Related
	}
	if len(v.Upstream) > 0 {
		meta[adapter.MetaKeyUpstream] = v.Upstream
	}
	if sev := collectSeverityEntries(v); len(sev) > 0 {
		meta[adapter.MetaKeySeverity] = sev
	}
	if len(v.Affected) > 0 {
		meta[adapter.MetaKeyAffected] = v.Affected
	}
	if len(v.References) > 0 {
		meta[adapter.MetaKeyReferences] = v.References
	}
	if len(v.DatabaseSpecific) > 0 {
		meta[adapter.MetaKeyDatabaseSpecific] = v.DatabaseSpecific
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// collectSeverityEntries returns top-level severity entries when present, or
// collects package-level severity entries across v.Affected so raw CVSS vectors
// are preserved in Finding.Metadata even when omitted at the top level (#98).
func collectSeverityEntries(v Vulnerability) []SeverityEntry {
	if len(v.Severity) > 0 {
		return v.Severity
	}
	var out []SeverityEntry
	for _, aff := range v.Affected {
		out = append(out, aff.Severity...)
	}
	return out
}
