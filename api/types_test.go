// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
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

	// Raw content populates ContentMeta (and leaves Digest/PURL empty).
	contentBytes := []byte("hello world")
	sum := sha256.Sum256(contentBytes)
	expectedHex := hex.EncodeToString(sum[:])

	a, err = ValidateAndNormalizeArtifact(ArtifactInput{
		Content:   contentBytes,
		Filename:  "hello.txt",
		MediaType: "text/plain",
	}, 1024)
	if err != nil {
		t.Fatalf("unexpected error for content: %v", err)
	}
	if a.ContentMeta == nil || a.ContentMeta.SizeBytes != 11 || a.ContentMeta.SHA256 != expectedHex {
		t.Fatalf("expected populated ContentMeta, got %+v", a)
	}
	if a.PURL != "" || a.Digest != "" {
		t.Fatalf("expected exclusive content artifact without purl/digest, got %+v", a)
	}

	// Multiple artifact types must fail closed (exclusive artifact types only).
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		PURL:   "pkg:npm/lodash@4.17.20",
		Digest: validDigest,
	}, 1024); err == nil {
		t.Fatal("expected error when both purl and digest are supplied")
	}
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		PURL:    "pkg:npm/lodash@4.17.20",
		Content: contentBytes,
	}, 1024); err == nil {
		t.Fatal("expected error when both purl and content are supplied")
	}
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		Digest:  validDigest,
		Content: contentBytes,
	}, 1024); err == nil {
		t.Fatal("expected error when both digest and content are supplied")
	}

	// Oversized content must fail.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{Content: []byte("too-long")}, 4); err == nil {
		t.Fatal("expected error when content exceeds maxBytes")
	}
}

func TestSubmissionStateMachineFailClosed(t *testing.T) {
	now := time.Now().UTC()
	var sub Submission

	// Cannot jump directly from empty to running or completed.
	if err := sub.TransitionTo(SubmissionRunning, "", now); err == nil {
		t.Fatal("expected error transitioning new submission directly to running")
	}

	// Valid progression: "" -> accepted -> running -> completed.
	if err := sub.TransitionTo(SubmissionAccepted, "", now); err != nil {
		t.Fatalf("TransitionTo(accepted) failed: %v", err)
	}
	if err := sub.TransitionTo(SubmissionRunning, "", now); err != nil {
		t.Fatalf("TransitionTo(running) failed: %v", err)
	}
	if err := sub.TransitionTo(SubmissionCompleted, "", now); err != nil {
		t.Fatalf("TransitionTo(completed) failed: %v", err)
	}

	// Terminal state cannot transition to failed or running.
	if err := sub.TransitionTo(SubmissionFailed, "err", now); err == nil {
		t.Fatal("expected error transitioning from completed to failed")
	}
	if err := sub.TransitionTo(SubmissionRunning, "", now); err == nil {
		t.Fatal("expected error transitioning from completed to running")
	}
}
