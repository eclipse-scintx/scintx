// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SchemaVersionV1 is the current public Eclipse SCINTX payload schema version.
const SchemaVersionV1 = "1"

// DefaultMaxContentBytes is the default 64 MiB limit for raw artifact uploads.
const DefaultMaxContentBytes int64 = 64 * 1024 * 1024

// ContentMetadata records metadata derived from raw artifact content bytes.
type ContentMetadata struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	Filename  string `json:"filename,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

// ArtifactInput represents the submitted artifact for evaluation.
// At least one of PURL, Digest, or Content must be supplied.
type ArtifactInput struct {
	PURL        string           `json:"purl,omitempty"`
	Digest      string           `json:"digest,omitempty"`
	Content     []byte           `json:"-"`
	Filename    string           `json:"-"`
	MediaType   string           `json:"-"`
	ContentMeta *ContentMetadata `json:"content,omitempty"`
}

// ValidateAndNormalizeArtifact validates the submitted artifact fields,
// canonicalizes any PURL, checks digest formatting, and computes SHA-256
// metadata when raw content bytes are supplied.
func ValidateAndNormalizeArtifact(in ArtifactInput, maxBytes int64) (ArtifactInput, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxContentBytes
	}
	out := ArtifactInput{
		PURL:      strings.TrimSpace(in.PURL),
		Digest:    strings.ToLower(strings.TrimSpace(in.Digest)),
		Content:   in.Content,
		Filename:  strings.TrimSpace(in.Filename),
		MediaType: strings.TrimSpace(in.MediaType),
	}

	// If raw content is uploaded without a PURL, check if it is a .vsix package.
	if out.PURL == "" && len(out.Content) > 0 && strings.HasSuffix(strings.ToLower(out.Filename), ".vsix") {
		if extracted := extractVSIXPURL(out.Content); extracted != "" {
			out.PURL = extracted
		}
	}

	if out.PURL == "" && out.Digest == "" && len(out.Content) == 0 {
		return ArtifactInput{}, fmt.Errorf("artifact requires at least one of purl, digest, or content")
	}

	if out.PURL != "" {
		canonical, err := CanonicalPurl(out.PURL)
		if err != nil {
			return ArtifactInput{}, fmt.Errorf("invalid purl: %w", err)
		}
		out.PURL = canonical
	}

	if out.Digest != "" {
		if err := ValidateDigest(out.Digest); err != nil {
			return ArtifactInput{}, err
		}
	}

	if len(out.Content) > 0 {
		if int64(len(out.Content)) > maxBytes {
			return ArtifactInput{}, fmt.Errorf("artifact content size %d exceeds maximum %d bytes", len(out.Content), maxBytes)
		}
		sum := sha256.Sum256(out.Content)
		hexSum := hex.EncodeToString(sum[:])
		if out.Digest == "" {
			out.Digest = "sha256:" + hexSum
		}
		out.ContentMeta = &ContentMetadata{
			SHA256:    hexSum,
			SizeBytes: int64(len(out.Content)),
			Filename:  out.Filename,
			MediaType: out.MediaType,
		}
	}

	return out, nil
}

// ValidateDigest verifies that a digest string uses a supported algorithm
// prefix (sha256, sha384, sha512) and valid hexadecimal characters.
func ValidateDigest(d string) error {
	parts := strings.SplitN(strings.ToLower(strings.TrimSpace(d)), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid digest %q: expected <algorithm>:<hex>", d)
	}
	alg, val := parts[0], parts[1]
	var expectedLen int
	switch alg {
	case "sha256":
		expectedLen = 64
	case "sha384":
		expectedLen = 96
	case "sha512":
		expectedLen = 128
	default:
		return fmt.Errorf("unsupported digest algorithm %q", alg)
	}
	if len(val) != expectedLen {
		return fmt.Errorf("invalid %s digest length: got %d hex chars, want %d", alg, len(val), expectedLen)
	}
	if _, err := hex.DecodeString(val); err != nil {
		return fmt.Errorf("invalid digest hex in %q: %w", d, err)
	}
	return nil
}
