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
		"pkg:npm/lodash@1.0.0#../secret",
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
