// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"net/url"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file maps OSV records and package coordinates into normalized SCINTX
// Findings while preserving identifiers, relationships, affected package
// context, and provider provenance (#94, #96, #98).

// openVSXEcosystem is the ecosystem string OSV uses for Open VSX / VS Code
// extension advisories when a direct PURL lookup returns no matches.
const openVSXEcosystem = "VSCode:https://open-vsx.org"

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
		Artifact: &adapter.ArtifactInput{
			PURL: artifactPURL,
		},
		Identifiers: collectIdentifiers(v),
		Metadata:    buildFindingMetadata(v),
	}
}

// collectIdentifiers returns a deduplicated list of advisory identifiers
// starting with the primary OSV ID followed by aliases and upstream IDs.
func collectIdentifiers(v Vulnerability) []string {
	seen := make(map[string]struct{}, 1+len(v.Aliases)+len(v.Upstream))
	var out []string
	add := func(id string) {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			return
		}
		if _, exists := seen[trimmed]; exists {
			return
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}

	add(v.ID)
	for _, alias := range v.Aliases {
		add(alias)
	}
	for _, up := range v.Upstream {
		add(up)
	}
	return out
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
	if len(v.Related) > 0 {
		meta[adapter.MetaKeyRelated] = v.Related
	}
	if len(v.Upstream) > 0 {
		meta[adapter.MetaKeyUpstream] = v.Upstream
	}
	if len(v.Severity) > 0 {
		meta[adapter.MetaKeySeverity] = v.Severity
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

// parseVSCodeExtensionPURL extracts "<publisher>.<name>" and "<version>" from
// a canonical "pkg:vscode-extension/<publisher>/<name>@<version>" PURL (#96).
func parseVSCodeExtensionPURL(purl string) (extName, version string, ok bool) {
	if !strings.HasPrefix(purl, vscodeExtensionPURLPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(purl, vscodeExtensionPURLPrefix)
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if at := strings.Index(rest, "@"); at >= 0 {
		rawVer, err := url.PathUnescape(rest[at+1:])
		if err != nil || rawVer == "" {
			return "", "", false
		}
		version = rawVer
		rest = rest[:at]
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "/") {
		return "", "", false
	}
	pub, err1 := url.PathUnescape(parts[0])
	name, err2 := url.PathUnescape(parts[1])
	if err1 != nil || err2 != nil || pub == "" || name == "" {
		return "", "", false
	}
	return pub + "." + name, version, true
}
