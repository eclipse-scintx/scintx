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
// The VS Code extension mapping lives in purl_vscode.go.

const (
	goOSVEcosystem           = "Go"
	alpineOSVEcosystemPrefix = "Alpine:"
	qualifierDistro          = "distro"
	golangPURLPrefix         = "pkg:" + string(adapter.EcosystemGolang) + "/"
	apkAlpinePURLPrefix      = "pkg:apk/alpine/"
)

// standardDistroPURL is the PURL spec type and namespace of one Linux distro.
type standardDistroPURL struct {
	purlType  string
	namespace string
}

// distroTypeToStandardPURL maps the Linux distro PURL types declared in #71
// ("debian", "ubuntu", "alpine", "rocky", "almalinux") onto the canonical PURL
// type and namespace ("pkg:deb/debian/", "pkg:apk/alpine/", "pkg:rpm/...")
// indexed by OSV.dev (#96).
var distroTypeToStandardPURL = map[string]standardDistroPURL{
	"pkg:debian/":    {"deb", "debian"},
	"pkg:ubuntu/":    {"deb", "ubuntu"},
	"pkg:alpine/":    {"apk", "alpine"},
	"pkg:rocky/":     {"rpm", "rocky-linux"},
	"pkg:almalinux/": {"rpm", "almalinux"},
}

// mapOSVQueryPURL translates non-standard distro-typed PURLs ("pkg:debian/...",
// "pkg:ubuntu/...", "pkg:alpine/...", "pkg:rocky/...", "pkg:almalinux/...") into
// the canonical PURL spec forms ("pkg:deb/...", "pkg:apk/...", "pkg:rpm/...")
// indexed by OSV (#96).
func mapOSVQueryPURL(canonicalPURL string) string {
	for prefix, std := range distroTypeToStandardPURL {
		rest, ok := strings.CutPrefix(canonicalPURL, prefix)
		if !ok {
			continue
		}
		// The caller may already repeat the distro as a namespace, for example
		// "pkg:debian/debian/openssl". Drop it so it is not added twice.
		rest = strings.TrimPrefix(rest, std.namespace+"/")
		return "pkg:" + std.purlType + "/" + std.namespace + "/" + rest
	}
	return canonicalPURL
}

// validateOSVQueryPURL fails closed on PURLs that OSV cannot answer correctly.
// An Alpine PURL without "?distro=" matches nothing on OSV, by PURL or by
// name, because OSV files every Alpine advisory under a release ("Alpine:v3.14").
// Without this check such a PURL would be reported as clean (#96).
func validateOSVQueryPURL(queryPURL string) error {
	rest, ok := strings.CutPrefix(queryPURL, apkAlpinePURLPrefix)
	if !ok {
		return nil
	}
	if _, rawQuery := splitPURLCoordAndQuery(rest); extractQualifier(rawQuery, qualifierDistro) != "" {
		return nil
	}
	return &adapter.AdapterError{
		Code:    adapter.ErrUnsupportedInput,
		Message: "osv adapter requires a distro qualifier on Alpine PURLs, for example ?distro=v3.14",
	}
}

// buildFallbackQueries returns ordered ecosystem+name+version fallback queries
// when OSV's PURL lookup strays from the PURL specification (#96).
func buildFallbackQueries(queryPURL string) []QueryRequest {
	if out := buildVSCodeQueries(queryPURL); out != nil {
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
