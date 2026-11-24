// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/yeeth-security/scintx/api"
)

func TestValidateAndNormalizeArtifact_PURL(t *testing.T) {
	input := &api.ArtifactInput{PURL: "pkg:NPM/Lodash@4.17.21"}
	if err := api.ValidateAndNormalizeArtifact(input, 1024); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("got purl %q, want canonical pkg:npm/lodash@4.17.21", input.PURL)
	}
}

func TestValidateAndNormalizeArtifact_Digest(t *testing.T) {
	sum := sha256.Sum256([]byte("hello"))
	hexVal := hex.EncodeToString(sum[:])

	input := &api.ArtifactInput{
		Digest: &api.Digest{Algorithm: "SHA256", Value: hexVal},
	}
	if err := api.ValidateAndNormalizeArtifact(input, 1024); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.Digest.Algorithm != "sha256" {
		t.Fatalf("expected lowercase sha256, got %q", input.Digest.Algorithm)
	}

	// Unsupported digest algorithm must fail validation.
	badAlg := &api.ArtifactInput{
		Digest: &api.Digest{Algorithm: "md5", Value: hexVal},
	}
	if err := api.ValidateAndNormalizeArtifact(badAlg, 1024); err == nil {
		t.Fatal("expected error for unsupported digest algorithm")
	}
}

func TestValidateAndNormalizeArtifact_VSIXContent(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("extension/package.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{"publisher":"eclipse","name":"sample-ext","version":"1.2.3"}`))
	_ = zw.Close()

	input := &api.ArtifactInput{
		Content:   buf.Bytes(),
		Filename:  "sample-ext-1.2.3.vsix",
		MediaType: "application/octet-stream",
	}
	if err := api.ValidateAndNormalizeArtifact(input, 1<<20); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.PURL != "pkg:vscode-extension/eclipse/sample-ext@1.2.3" {
		t.Fatalf("got derived PURL %q, want pkg:vscode-extension/eclipse/sample-ext@1.2.3", input.PURL)
	}
	if input.Digest == nil || input.Digest.Algorithm != "sha256" || input.Digest.Value == "" {
		t.Fatalf("expected calculated sha256 digest, got %+v", input.Digest)
	}
}

func TestValidateAndNormalizeArtifact_RejectsEmptyAndOversized(t *testing.T) {
	if err := api.ValidateAndNormalizeArtifact(&api.ArtifactInput{}, 100); err == nil {
		t.Fatal("expected error for empty artifact input")
	}
	oversized := &api.ArtifactInput{Content: make([]byte, 101)}
	if err := api.ValidateAndNormalizeArtifact(oversized, 100); err == nil {
		t.Fatal("expected error when content exceeds maxBytes")
	}
}
