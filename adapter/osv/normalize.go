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

const (
	// openVSXEcosystem is the primary ecosystem string OSV uses for Open VSX
	// extension advisories when a direct PURL lookup returns no matches (#96).
	openVSXEcosystem = "VSCode:https://open-vsx.org"

	// vscodeEcosystem is the parent OSV ecosystem string for VS Code extensions.
	vscodeEcosystem = "VSCode"

	// goOSVEcosystem is the OSV ecosystem string for Go modules.
	goOSVEcosystem = "Go"

	// qualifierRepositoryURL is the standard PURL qualifier key used to specify
	// a non-default registry such as https://open-vsx.org (#96).
	qualifierRepositoryURL = "repository_url"

	// golangPURLPrefix is the canonical PURL prefix for Go module PURLs.
	golangPURLPrefix = "pkg:" + string(adapter.EcosystemGolang) + "/"
)

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

// parseVSCodeExtensionPURL extracts "<publisher>.<name>", "<version>", and the
// target OSV ecosystem(s) from a canonical "pkg:vscode-extension/<publisher>/<name>@<version>"
// PURL, honoring the "?repository_url=..." qualifier when present (#96).
func parseVSCodeExtensionPURL(purl string) (extName, version string, ecosystems []string, ok bool) {
	if !strings.HasPrefix(purl, vscodeExtensionPURLPrefix) {
		return "", "", nil, false
	}
	rest := strings.TrimPrefix(purl, vscodeExtensionPURLPrefix)
	if hash := strings.IndexByte(rest, '#'); hash >= 0 {
		rest = rest[:hash]
	}
	var rawQuery string
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		rawQuery = rest[q+1:]
		rest = rest[:q]
	}
	at := strings.IndexByte(rest, '@')
	if at <= 0 {
		return "", "", nil, false
	}
	rawVer, err := url.PathUnescape(rest[at+1:])
	if err != nil || rawVer == "" {
		return "", "", nil, false
	}
	parts := strings.SplitN(rest[:at], "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "/") {
		return "", "", nil, false
	}
	pub, err1 := url.PathUnescape(parts[0])
	name, err2 := url.PathUnescape(parts[1])
	if err1 != nil || err2 != nil || pub == "" || name == "" {
		return "", "", nil, false
	}
	return pub + "." + name, rawVer, resolveVSCodeEcosystems(rawQuery), true
}

// resolveVSCodeEcosystems maps a PURL query string's repository_url qualifier
// to the corresponding OSV ecosystem(s) (#96).
func resolveVSCodeEcosystems(rawQuery string) []string {
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, found := strings.Cut(kv, "=")
		if !found || k != qualifierRepositoryURL {
			continue
		}
		repoURL, err := url.PathUnescape(v)
		if err != nil {
			break
		}
		repoURL = strings.TrimRight(strings.TrimSpace(repoURL), "/")
		if repoURL == "" {
			break
		}
		if strings.Contains(strings.ToLower(repoURL), "marketplace.visualstudio.com") {
			return []string{vscodeEcosystem}
		}
		return []string{vscodeEcosystem + ":" + repoURL}
	}
	return []string{openVSXEcosystem, vscodeEcosystem}
}

// parseMixedCaseGolangPURL extracts the Go module path and version when a
// canonical pkg:golang PURL contains uppercase ASCII characters that OSV's
// server-side PURL lookup folds to lowercase (#96).
func parseMixedCaseGolangPURL(purl string) (modulePath, version string, ok bool) {
	if !strings.HasPrefix(purl, golangPURLPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(purl, golangPURLPrefix)
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndexByte(rest, '@')
	if at <= 0 {
		return "", "", false
	}
	modPath := rest[:at]
	if modPath == strings.ToLower(modPath) {
		return "", "", false
	}
	ver, err := url.PathUnescape(rest[at+1:])
	if err != nil || ver == "" {
		return "", "", false
	}
	if len(ver) > 1 && (ver[0] == 'v' || ver[0] == 'V') && ver[1] >= '0' && ver[1] <= '9' {
		ver = ver[1:]
	}
	return modPath, ver, true
}
