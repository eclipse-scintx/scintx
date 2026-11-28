// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package ossindex

import (
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file maps OSS Index ComponentReport and Vulnerability entries into
// normalized SCINTX Findings while preserving CVE/Sonatype identifiers, CVSS
// scores and vectors, CWEs, affected version ranges, and component provenance (#98).

// normalizeFinding converts one OSS Index Vulnerability and its enclosing
// ComponentReport into a normalized SCINTX adapter.Finding.
func normalizeFinding(comp ComponentReport, v Vulnerability, artifactPURL string) adapter.Finding {
	title := strings.TrimSpace(v.Title)
	if title == "" {
		title = strings.TrimSpace(v.DisplayName)
	}
	if title == "" {
		title = v.ID
	}

	return adapter.Finding{
		ID:          v.ID,
		Type:        adapter.FindingTypeVulnerability,
		Severity:    extractSeverity(v),
		Title:       title,
		Description: v.Description,
		Artifact: &adapter.ArtifactInput{
			PURL: artifactPURL,
		},
		Identifiers: adapter.DeduplicateStrings(v.ID, v.CVE, v.DisplayName),
		Metadata:    buildFindingMetadata(comp, v),
	}
}

// extractSeverity maps an OSS Index vulnerability's numeric cvssScore onto the
// standardized SCINTX Severity scale using the shared adapter helper (#72, #98).
func extractSeverity(v Vulnerability) adapter.Severity {
	if v.CVSSScore != nil {
		if sev, ok := adapter.SeverityFromCVSSFloat(*v.CVSSScore); ok {
			return sev
		}
	}
	return adapter.SeverityUnknown
}

// buildFindingMetadata preserves OSS Index vulnerability attributes (CVE, CWE,
// CVSS score/vector, affected versionRanges, advisory references) and component
// provenance using the shared adapter.MetaKey* constants (#98).
func buildFindingMetadata(comp ComponentReport, v Vulnerability) map[string]any {
	meta := make(map[string]any)
	if v.DisplayName != "" {
		meta[adapter.MetaKeyDisplayName] = v.DisplayName
	}
	if v.CVE != "" {
		meta[adapter.MetaKeyCVE] = v.CVE
	}
	if v.CWE != "" {
		meta[adapter.MetaKeyCWE] = v.CWE
	}
	if v.CVSSScore != nil {
		meta[adapter.MetaKeyCVSSScore] = *v.CVSSScore
	}
	if v.CVSSVector != "" {
		meta[adapter.MetaKeyCVSSVector] = v.CVSSVector
	}
	if len(v.VersionRanges) > 0 {
		meta[adapter.MetaKeyVersionRanges] = v.VersionRanges
	}
	if refs := adapter.DeduplicateStrings(append([]string{v.Reference}, v.ExternalReferences...)...); len(refs) > 0 {
		meta[adapter.MetaKeyReferences] = refs
	}
	if comp.Coordinates != "" {
		meta[adapter.MetaKeyComponentCoordinates] = comp.Coordinates
	}
	if comp.Reference != "" {
		meta[adapter.MetaKeyComponentReference] = comp.Reference
	}
	if comp.Description != "" {
		meta[adapter.MetaKeyComponentDescription] = comp.Description
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}
