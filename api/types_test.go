// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	// Multiple artifact types must fail closed (exclusive artifact types only).
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		PURL:   "pkg:npm/lodash@4.17.20",
		Digest: validDigest,
	}, 1024); err == nil {
		t.Fatal("expected error when both purl and digest are supplied")
	}
}

// TestValidateUploadedContent covers the streamed upload path. It was split
// from the test above when uploads stopped being buffered in memory.
func TestValidateUploadedContent(t *testing.T) {
	validDigest := "sha256:" + strings.Repeat("a", 64)
	contentBytes := []byte("hello world")
	sum := sha256.Sum256(contentBytes)
	expectedHex := hex.EncodeToString(sum[:])

	// An uploaded file is hashed as a stream. Validation then fills in
	// ContentMeta, strips MediaType parameters, and clears Upload.
	a, err := ValidateAndNormalizeArtifact(ArtifactInput{
		Upload: uploadOf(t, contentBytes, "hello.txt", "Text/Plain; charset=utf-8"),
	}, 1024)
	if err != nil {
		t.Fatalf("unexpected error for content: %v", err)
	}
	if a.ContentMeta == nil || a.ContentMeta.SizeBytes != 11 || a.ContentMeta.SHA256 != expectedHex {
		t.Fatalf("expected populated ContentMeta, got %+v", a)
	}
	if a.ContentMeta.MediaType != "text/plain" {
		t.Fatalf("expected canonical mediaType text/plain, got %q", a.ContentMeta.MediaType)
	}
	if a.Upload != nil {
		t.Fatal("expected raw Upload facts to be cleared after validation")
	}
	if a.PURL != "" || a.Digest != "" {
		t.Fatalf("expected exclusive content artifact without purl/digest, got %+v", a)
	}

	// Malicious filename or mediaType must fail closed.
	for _, badName := range []string{"../evil.tgz", "dir/evil.tgz", `dir\evil.tgz`, "evil\x00.tgz", "evil\r\n.tgz", "..", strings.Repeat("a", 256)} {
		if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
			Upload: uploadOf(t, contentBytes, badName, ""),
		}, 1024); err == nil {
			t.Fatalf("expected filename %q to fail closed", badName)
		}
	}
	for _, badMT := range []string{"not a mime type", "application/json\r\nX-Evil: 1", strings.Repeat("a", 130)} {
		if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
			Upload: uploadOf(t, contentBytes, "", badMT),
		}, 1024); err == nil {
			t.Fatalf("expected mediaType %q to fail closed", badMT)
		}
	}

	// Content together with a purl or a digest must fail closed.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		PURL:   "pkg:npm/lodash@4.17.20",
		Upload: uploadOf(t, contentBytes, "", ""),
	}, 1024); err == nil {
		t.Fatal("expected error when both purl and content are supplied")
	}
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		Digest: validDigest,
		Upload: uploadOf(t, contentBytes, "", ""),
	}, 1024); err == nil {
		t.Fatal("expected error when both digest and content are supplied")
	}

	// Oversized content must fail, both while streaming and in validation.
	if _, _, err := HashContent(bytes.NewReader([]byte("too-long")), 4); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation when the stream exceeds maxBytes, got %v", err)
	}
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{Upload: uploadOf(t, []byte("too-long"), "", "")}, 4); err == nil {
		t.Fatal("expected error when content exceeds maxBytes")
	}

	// An empty upload must fail closed.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{Upload: uploadOf(t, nil, "empty.bin", "")}, 1024); err == nil {
		t.Fatal("expected error for an empty upload")
	}

	// A client must not supply server-computed content metadata. Before the
	// fix this object was silently dropped and the request was accepted.
	if _, err := ValidateAndNormalizeArtifact(ArtifactInput{
		PURL:        "pkg:npm/lodash@4.17.20",
		ContentMeta: &ContentMetadata{SHA256: expectedHex, SizeBytes: 11},
	}, 1024); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for client-supplied content metadata, got %v", err)
	}
}

// uploadOf hashes data the same way the HTTP handler does and returns the
// measured upload facts. The limit is large so the helper itself never fails.
func uploadOf(t *testing.T, data []byte, filename, mediaType string) *ContentMetadata {
	t.Helper()
	sum, size, err := HashContent(bytes.NewReader(data), 1<<20)
	if err != nil {
		t.Fatalf("HashContent failed: %v", err)
	}
	return &ContentMetadata{SHA256: sum, SizeBytes: size, Filename: filename, MediaType: mediaType}
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
