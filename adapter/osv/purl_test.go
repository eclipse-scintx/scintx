// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"errors"
	"testing"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file tests the PURL to OSV query mapping without a network (#96).

// fallbackFor canonicalizes rawPURL the same way Evaluate does and returns the
// fallback queries the adapter would send to OSV.
func fallbackFor(t *testing.T, rawPURL string) []QueryRequest {
	t.Helper()
	canonical, _, err := adapter.ValidateVersionedPURL(AdapterSlug, rawPURL, supportedPURLTypes)
	if err != nil {
		t.Fatalf("ValidateVersionedPURL(%q): %v", rawPURL, err)
	}
	return buildFallbackQueries(mapOSVQueryPURL(canonical))
}

// TestMapOSVQueryPURL verifies the distro-typed PURL aliases, including the
// form that already repeats the distro as a namespace (#96).
func TestMapOSVQueryPURL(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:debian/openssl@1.1.1k-1":          "pkg:deb/debian/openssl@1.1.1k-1",
		"pkg:debian/debian/openssl@1.1.1k-1":   "pkg:deb/debian/openssl@1.1.1k-1",
		"pkg:ubuntu/openssl@1.1.1f":            "pkg:deb/ubuntu/openssl@1.1.1f",
		"pkg:alpine/openssl@1.1.1k-r0":         "pkg:apk/alpine/openssl@1.1.1k-r0",
		"pkg:rocky/openssl@1.1.1k":             "pkg:rpm/rocky-linux/openssl@1.1.1k",
		"pkg:rocky/rocky-linux/openssl@1.1.1k": "pkg:rpm/rocky-linux/openssl@1.1.1k",
		"pkg:almalinux/openssl@1.1.1k":         "pkg:rpm/almalinux/openssl@1.1.1k",
		// Standard PURL types pass through unchanged.
		"pkg:deb/debian/openssl@1.1.1k-1": "pkg:deb/debian/openssl@1.1.1k-1",
		"pkg:npm/lodash@4.17.20":          "pkg:npm/lodash@4.17.20",
	} {
		if got := mapOSVQueryPURL(in); got != want {
			t.Fatalf("mapOSVQueryPURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVSCodeEcosystemFromRepositoryURL verifies that the registry URL is
// compared by host, without regard to case, before it becomes the OSV
// ecosystem string. OSV compares that string exactly (#96).
func TestVSCodeEcosystemFromRepositoryURL(t *testing.T) {
	const base = "pkg:vscode-extension/acme/theme-pro@1.0.2"
	for qualifier, want := range map[string]string{
		"":                                     "VSCode",
		"?repository_url=https://open-vsx.org": "VSCode:https://open-vsx.org",
		// Host and scheme case must not change the ecosystem.
		"?repository_url=HTTPS://Open-VSX.org/": "VSCode:https://open-vsx.org",
		// The Marketplace is the default ecosystem, with or without a path.
		"?repository_url=https://Marketplace.VisualStudio.com/vscode": "VSCode",
		// A look-alike host is not the Marketplace.
		"?repository_url=https://notmarketplace.visualstudio.com.evil.example": "VSCode:https://notmarketplace.visualstudio.com.evil.example",
	} {
		got := fallbackFor(t, base+qualifier)
		if len(got) != 1 || got[0].Package.Ecosystem != want || got[0].Package.Name != "acme.theme-pro" {
			t.Fatalf("%q: got %+v, want ecosystem %q", qualifier, got, want)
		}
	}
}

// TestAlpineRequiresDistroQualifier verifies that an Alpine PURL without a
// release fails closed. OSV has no release-free Alpine records, so the query
// would return nothing and look clean (#96).
func TestAlpineRequiresDistroQualifier(t *testing.T) {
	for _, purl := range []string{
		"pkg:apk/alpine/openssl@1.1.1k-r0",
		"pkg:apk/alpine/openssl@1.1.1k-r0?arch=x86_64",
		"pkg:alpine/openssl@1.1.1k-r0",
	} {
		err := validateOSVQueryPURL(mapOSVQueryPURL(purl))
		var ae *adapter.AdapterError
		if !errors.As(err, &ae) || ae.Code != adapter.ErrUnsupportedInput || ae.Retryable {
			t.Fatalf("%s: expected non-retryable ErrUnsupportedInput, got %v", purl, err)
		}
	}
	for _, purl := range []string{
		"pkg:apk/alpine/openssl@1.1.1k-r0?distro=v3.14",
		"pkg:alpine/openssl@1.1.1k-r0?arch=x86_64&distro=3.14",
		"pkg:deb/debian/openssl@1.1.1k-1",
		"pkg:npm/lodash@4.17.20",
	} {
		if err := validateOSVQueryPURL(mapOSVQueryPURL(purl)); err != nil {
			t.Fatalf("%s: unexpected error %v", purl, err)
		}
	}
}

// TestFallbackNamesArePercentDecoded verifies that fallback queries send the
// plain package name to OSV. The canonical PURL encodes "+" as "%2B". Sending
// the encoded name matched nothing and reported the package as clean (#96).
func TestFallbackNamesArePercentDecoded(t *testing.T) {
	for _, tc := range []struct {
		purl, ecosystem, name, version string
	}{
		{"pkg:apk/alpine/libstdc++@10.3.1-r0?distro=v3.14", "Alpine:v3.14", "libstdc++", "10.3.1-r0"},
		{"pkg:alpine/g++@10.3.1-r0?distro=3.14", "Alpine:v3.14", "g++", "10.3.1-r0"},
		{"pkg:golang/github.com/Foo/a+b@v1.0.0", goOSVEcosystem, "github.com/Foo/a+b", "1.0.0"},
	} {
		got := fallbackFor(t, tc.purl)
		if len(got) != 1 || got[0].Package.Ecosystem != tc.ecosystem || got[0].Package.Name != tc.name || got[0].Version != tc.version {
			t.Fatalf("%s: got %+v, want one query for (%s, %s, %s)", tc.purl, got, tc.ecosystem, tc.name, tc.version)
		}
	}
}
