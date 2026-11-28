// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api_test

import (
	"strings"
	"testing"

	"github.com/eclipse-scintx/scintx/api"
)

func TestCanonicalPurl_LowercasesPyPI(t *testing.T) {
	got, err := api.CanonicalPurl("pkg:PYPI/Requests@2.32.3")
	if err != nil {
		t.Fatal(err)
	}
	want := "pkg:pypi/requests@2.32.3"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalPurl_DecodesAndFoldsCase(t *testing.T) {
	cases := map[string]string{
		// Encoded and raw scope are the same package.
		"pkg:npm/%40angular/core@1.0.0": "pkg:npm/%40angular/core@1.0.0",
		"pkg:npm/@angular/core@1.0.0":   "pkg:npm/%40angular/core@1.0.0",
		// GitHub names are not case sensitive.
		"pkg:github/Org/Repo@1": "pkg:github/org/repo@1",
		// Go module paths, RubyGems names, and RPM package names are case-sensitive (#96).
		"pkg:golang/github.com/Masterminds/vcs@1.13.0":  "pkg:golang/github.com/Masterminds/vcs@1.13.0",
		"pkg:gem/RedCloth@4.2.9":                        "pkg:gem/RedCloth@4.2.9",
		"pkg:rpm/AlmaLinux/NetworkManager@1.30.0-7.el8": "pkg:rpm/almalinux/NetworkManager@1.30.0-7.el8",
		"pkg:apk/ALPINE/OpenSSL@1.1.1k-r0?distro=v3.14": "pkg:apk/alpine/openssl@1.1.1k-r0?distro=v3.14",
		"pkg:pub/HTTP@0.13.0":                           "pkg:pub/http@0.13.0",
		// PyPI package names fold case and replace '_' with '-' (#96).
		"pkg:pypi/Django_Debug_Toolbar@3.2": "pkg:pypi/django-debug-toolbar@3.2",
		// "+" is not unreserved, so the canonical form encodes it.
		"pkg:npm/foo@1.0.0+build": "pkg:npm/foo@1.0.0%2Bbuild",
	}
	for in, want := range cases {
		got, err := api.CanonicalPurl(in)
		if err != nil {
			t.Fatalf("CanonicalPurl(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("CanonicalPurl(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalPurl_SortsQualifiers(t *testing.T) {
	got, err := api.CanonicalPurl("pkg:npm/foo@1.0.0?b=2&a=1")
	if err != nil {
		t.Fatal(err)
	}
	want := "pkg:npm/foo@1.0.0?a=1&b=2"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCanonicalPurl_RejectsMaliciousInputs(t *testing.T) {
	cases := []string{
		"not-a-purl",
		"pkg:npm/lodash@4.17.20\r\nInjected: header",
		"pkg:npm/lodash@4.17.20 with space",
		"pkg:npm/../etc/passwd@1.0.0",
		"pkg:npm/%2e%2e/etc/passwd@1.0.0",
		"pkg:npm/%2E%2E/etc/passwd@1.0.0",
		"pkg:npm/lodash@1.0.0#../secret",
		"pkg:npm/lodash@1.0.0#%2e%2e/secret",
		"pkg:npm/lodash@1.0.0#%ZZ",
		"pkg:npm/lodash@1.0.0@2.0.0",
		"pkg:npm/lodash@",
		"pkg:123invalid/lodash@1.0.0",
		"pkg:npm/lodash@1.0.0?a=1&a=2",
		"pkg:npm/lodash@1.0.0?badkey=",
		"pkg:npm/" + strings.Repeat("a", api.MaxPurlLength),
	}
	for _, tc := range cases {
		if _, err := api.CanonicalPurl(tc); err == nil {
			t.Fatalf("expected CanonicalPurl(%q) to fail closed", tc)
		}
	}
}

func TestPurlTypeAndVersion(t *testing.T) {
	typ, err := api.PurlType("pkg:npm/left-pad@1.3.0")
	if err != nil || typ != "npm" {
		t.Fatalf("type=%q err=%v", typ, err)
	}
	ver, ok, err := api.PurlVersion("pkg:npm/left-pad@1.3.0")
	if err != nil || !ok || ver != "1.3.0" {
		t.Fatalf("ver=%q ok=%v err=%v", ver, ok, err)
	}
}
