// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"strings"
	"testing"
)

func TestValidateAndNormalizeArtifact(t *testing.T) {
	// Empty artifact must fail validation.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{}, 1024); err == nil {
		t.Fatal("expected error for empty artifact")
	}

	// Valid PURL normalizes cleanly.
	a, err := ValidateAndNormalizeArtifact(ArtifactInput{PURL: "pkg:NPM/lodash@4.17.20"}, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("got %q, want pkg:npm/lodash@4.17.20", a.PURL)
	}

	// Valid SHA-256 digest succeeds.
	validDigest := "sha256:" + strings.Repeat("a", 64)
	a, err = ValidateAndNormalizeArtifact(ArtifactInput{Digest: validDigest}, 1024)
	if err != nil || a.Digest != validDigest {
		t.Fatalf("unexpected digest validation result: %v, %+v", err, a)
	}

	// Invalid digest algorithm or length must fail.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{Digest: "md5:1234"}, 1024); err == nil {
		t.Fatal("expected error for unsupported digest algorithm")
	}
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{Digest: "sha256:1234"}, 1024); err == nil {
		t.Fatal("expected error for short sha256 digest")
	}

	// Raw content populates ContentMeta and SHA-256 digest.
	a, err = ValidateAndNormalizeArtifact(ArtifactInput{
		Content:   []byte("hello world"),
		Filename:  "hello.txt",
		MediaType: "text/plain",
	}, 1024)
	if err != nil {
		t.Fatalf("unexpected error for content: %v", err)
	}
	if a.ContentMeta == nil || a.ContentMeta.SizeBytes != 11 || !strings.HasPrefix(a.Digest, "sha256:") {
		t.Fatalf("expected populated ContentMeta and Digest, got %+v", a)
	}

	// Oversized content must fail.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{Content: []byte("too-long")}, 4); err == nil {
		t.Fatal("expected error when content exceeds maxBytes")
	}
}
