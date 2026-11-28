// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
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
