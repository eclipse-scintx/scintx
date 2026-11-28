// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"net/url"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file translates canonical PURLs into OSV query requests and documents
// every place where OSV.dev strays from the PURL specification (#96).

const (
	// vscodeEcosystem is the default OSV ecosystem string for VS Code extensions
	// (Microsoft Visual Studio Marketplace) when repository_url is omitted (#96).
	vscodeEcosystem           = "VSCode"
	goOSVEcosystem            = "Go"
	alpineOSVEcosystemPrefix  = "Alpine:"
	qualifierRepositoryURL    = "repository_url"
	qualifierDistro           = "distro"
	vscodeExtensionPURLPrefix = "pkg:" + string(adapter.EcosystemVSCodeExtension) + "/"
	golangPURLPrefix          = "pkg:" + string(adapter.EcosystemGolang) + "/"
	apkAlpinePURLPrefix       = "pkg:apk/alpine/"
	// marketplaceHost is the host of the Microsoft Visual Studio Marketplace.
	marketplaceHost = "marketplace.visualstudio.com"
)

// distroTypeToStandardPURLPrefix maps the Linux distro PURL types declared in
// #71 ("debian", "ubuntu", "alpine", "rocky", "almalinux") onto the canonical
// PURL type+namespace prefixes ("pkg:deb/...", "pkg:apk/...", "pkg:rpm/...")
// indexed by OSV.dev (#96).
var distroTypeToStandardPURLPrefix = map[string]string{
	"pkg:debian/":    "pkg:deb/debian/",
	"pkg:ubuntu/":    "pkg:deb/ubuntu/",
	"pkg:alpine/":    "pkg:apk/alpine/",
	"pkg:rocky/":     "pkg:rpm/rocky-linux/",
	"pkg:almalinux/": "pkg:rpm/almalinux/",
}

// mapOSVQueryPURL translates non-standard distro-typed PURLs ("pkg:debian/...",
// "pkg:ubuntu/...", "pkg:alpine/...", "pkg:rocky/...", "pkg:almalinux/...") into
// the canonical PURL spec forms ("pkg:deb/...", "pkg:apk/...", "pkg:rpm/...")
// indexed by OSV (#96).
func mapOSVQueryPURL(canonicalPURL string) string {
	for prefix, replacement := range distroTypeToStandardPURLPrefix {
		if strings.HasPrefix(canonicalPURL, prefix) {
			rest := strings.TrimPrefix(canonicalPURL, prefix)
			ns := replacement[strings.IndexByte(replacement[4:], '/')+5:]
			if strings.HasPrefix(rest, ns) {
				return "pkg:" + replacement[4:strings.IndexByte(replacement[4:], '/')+5] + rest
			}
			return replacement + rest
		}
	}
	return canonicalPURL
}

// buildFallbackQueries returns ordered ecosystem+name+version fallback queries
// when OSV's PURL lookup strays from the PURL specification (#96).
func buildFallbackQueries(queryPURL string) []QueryRequest {
	if extName, ver, eco, ok := parseVSCodeExtensionPURL(queryPURL); ok {
		out := []QueryRequest{{Package: &PackageQuery{Ecosystem: eco, Name: extName}, Version: ver}}
		// OSV's VSCode ecosystem performs case-sensitive package.name matching and
		// stores a mix of original-case ("ms-python.python") and lowercase records.
		if lower := strings.ToLower(extName); lower != extName {
			out = append(out, QueryRequest{Package: &PackageQuery{Ecosystem: eco, Name: lower}, Version: ver})
		}
		return out
	}
	if modPath, ver, ok := parseMixedCaseGolangPURL(queryPURL); ok {
		return []QueryRequest{{Package: &PackageQuery{Ecosystem: goOSVEcosystem, Name: modPath}, Version: ver}}
	}
	if pkgName, ver, eco, ok := parseAlpineDistroPURL(queryPURL); ok {
		return []QueryRequest{{Package: &PackageQuery{Ecosystem: eco, Name: pkgName}, Version: ver}}
	}
	return nil
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

// parseMixedCaseGolangPURL works around an OSV provider deviation from the PURL
// spec: Go module paths are case-sensitive in the PURL spec and in OSV's stored
// records, but OSV's /v1/query PURL endpoint lowercases pkg:golang paths before
// lookup and misses mixed-case modules unless queried via ecosystem="Go" (#96).
func parseMixedCaseGolangPURL(purl string) (modulePath, version string, ok bool) {
	if !strings.HasPrefix(purl, golangPURLPrefix) {
		return "", "", false
	}
	coord, _ := splitPURLCoordAndQuery(strings.TrimPrefix(purl, golangPURLPrefix))
	modPath, ver, ok := splitNameAndVersion(coord)
	if !ok || modPath == strings.ToLower(modPath) {
		return "", "", false
	}
	// OSV stores Go versions without a leading "v" prefix even though Go PURLs
	// commonly include "v" (for example "@v1.13.0").
	if len(ver) > 1 && (ver[0] == 'v' || ver[0] == 'V') && ver[1] >= '0' && ver[1] <= '9' {
		ver = ver[1:]
	}
	return modPath, ver, true
}

// parseAlpineDistroPURL works around an OSV provider deviation from the PURL
// spec: Alpine PURLs specify the release via "?distro=<vX.Y>", but OSV's Alpine
// records omit "?distro=" from package.purl and encode the branch only in
// package.ecosystem ("Alpine:vX.Y") (#96).
func parseAlpineDistroPURL(purl string) (pkgName, version, ecosystem string, ok bool) {
	if !strings.HasPrefix(purl, apkAlpinePURLPrefix) {
		return "", "", "", false
	}
	coord, rawQuery := splitPURLCoordAndQuery(strings.TrimPrefix(purl, apkAlpinePURLPrefix))
	name, ver, ok := splitNameAndVersion(coord)
	if !ok || strings.Contains(name, "/") {
		return "", "", "", false
	}
	distro := strings.TrimPrefix(strings.ToLower(extractQualifier(rawQuery, qualifierDistro)), "alpine-")
	if distro == "" {
		return "", "", "", false
	}
	if distro[0] >= '0' && distro[0] <= '9' {
		distro = "v" + distro
	}
	return name, ver, alpineOSVEcosystemPrefix + distro, true
}

func splitPURLCoordAndQuery(rest string) (coord, rawQuery string) {
	if hash := strings.IndexByte(rest, '#'); hash >= 0 {
		rest = rest[:hash]
	}
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		return rest[:q], rest[q+1:]
	}
	return rest, ""
}

// splitNameAndVersion splits "<name>@<version>" and percent-decodes both parts.
// The name must be decoded too. A canonical PURL encodes "+" as "%2B", so
// "libstdc++" arrives as "libstdc%2B%2B". OSV stores the plain name, and an
// encoded name never matches, which reported the package as clean (#96).
func splitNameAndVersion(coord string) (name, version string, ok bool) {
	at := strings.LastIndexByte(coord, '@')
	if at <= 0 {
		return "", "", false
	}
	name, nameErr := url.PathUnescape(coord[:at])
	ver, verErr := url.PathUnescape(coord[at+1:])
	if nameErr != nil || verErr != nil || name == "" || ver == "" {
		return "", "", false
	}
	return name, ver, true
}

func extractQualifier(rawQuery, key string) string {
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, v, found := strings.Cut(kv, "="); found && k == key {
			if decoded, err := url.PathUnescape(v); err == nil {
				return strings.TrimSpace(decoded)
			}
		}
	}
	return ""
}
