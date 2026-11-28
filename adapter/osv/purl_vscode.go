// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"net/url"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file maps pkg:vscode-extension PURLs onto OSV's VSCode ecosystems.
// It was split out of purl.go to keep both files small (#96).

const (
	// vscodeEcosystem is the default OSV ecosystem string for VS Code extensions
	// (Microsoft Visual Studio Marketplace) when repository_url is omitted (#96).
	vscodeEcosystem           = "VSCode"
	qualifierRepositoryURL    = "repository_url"
	vscodeExtensionPURLPrefix = "pkg:" + string(adapter.EcosystemVSCodeExtension) + "/"
	// marketplaceHost is the host of the Microsoft Visual Studio Marketplace.
	marketplaceHost = "marketplace.visualstudio.com"
)

// buildVSCodeQueries returns the OSV queries for a pkg:vscode-extension PURL,
// or nil for any other PURL type (#96).
//
// Known limit: OSV matches package.name case-sensitively, and it stores some
// names in mixed case ("CodeInKlingon.git-worktree-menu"). We try the
// submitted case and then lowercase. A lowercase PURL can therefore still miss
// a record that OSV stores in mixed case, because the original case is not
// recoverable from the PURL. Submit the registry's exact case to be safe.
func buildVSCodeQueries(queryPURL string) []QueryRequest {
	extName, ver, eco, ok := parseVSCodeExtensionPURL(queryPURL)
	if !ok {
		return nil
	}
	out := []QueryRequest{{Package: &PackageQuery{Ecosystem: eco, Name: extName}, Version: ver}}
	// OSV's VSCode ecosystem performs case-sensitive package.name matching and
	// stores a mix of original-case ("ms-python.python") and lowercase records.
	if lower := strings.ToLower(extName); lower != extName {
		out = append(out, QueryRequest{Package: &PackageQuery{Ecosystem: eco, Name: lower}, Version: ver})
	}
	return out
}

// parseVSCodeExtensionPURL works around an OSV provider deviation from the PURL
// spec: OSV's VSCode and VSCode:https://open-vsx.org advisories omit package.purl
// entirely and join "<publisher>.<name>" in package.name instead of the PURL
// spec's "<publisher>/<name>" namespace/name layout (#96).
func parseVSCodeExtensionPURL(purl string) (extName, version, ecosystem string, ok bool) {
	if !strings.HasPrefix(purl, vscodeExtensionPURLPrefix) {
		return "", "", "", false
	}
	coord, rawQuery := splitPURLCoordAndQuery(strings.TrimPrefix(purl, vscodeExtensionPURLPrefix))
	// splitNameAndVersion already percent-decodes the "<publisher>/<name>" part.
	namePart, ver, ok := splitNameAndVersion(coord)
	if !ok {
		return "", "", "", false
	}
	parts := strings.SplitN(namePart, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[1], "/") {
		return "", "", "", false
	}
	return parts[0] + "." + parts[1], ver, resolveVSCodeEcosystem(rawQuery), true
}

// resolveVSCodeEcosystem maps the PURL spec's optional repository_url qualifier
// onto OSV's VSCode ecosystem naming ("VSCode" by default for Microsoft Visual
// Studio Marketplace, or "VSCode:<repository_url>" for Open VSX) (#96).
//
// The scheme and host are lowercased first. URL hosts are not case sensitive,
// but OSV compares the ecosystem string exactly, so "https://Open-VSX.org"
// matched nothing and a malicious extension was reported as clean.
//
// The Marketplace is detected by its exact host (or a subdomain of it). The
// old substring test also accepted hosts such as
// "notmarketplace.visualstudio.com.evil.example".
func resolveVSCodeEcosystem(rawQuery string) string {
	repoURL := strings.TrimRight(extractQualifier(rawQuery, qualifierRepositoryURL), "/")
	if repoURL == "" {
		return vscodeEcosystem
	}
	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Host == "" {
		// Not a usable URL. Pass it through unchanged; OSV will match nothing.
		return vscodeEcosystem + ":" + repoURL
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if host := parsed.Hostname(); host == marketplaceHost || strings.HasSuffix(host, "."+marketplaceHost) {
		return vscodeEcosystem
	}
	return vscodeEcosystem + ":" + strings.TrimRight(parsed.String(), "/")
}
