// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"strings"
)

// ErrValidation is the sentinel error wrapped by all artifact input validation
// failures so HTTP handlers can distinguish 422 validation errors from 500
// storage failures.
var ErrValidation = errors.New("validation failed")

// SchemaVersionV1 is the current public Eclipse SCINTX payload schema version.
const SchemaVersionV1 = "1"

// DefaultMaxContentBytes is the default 64 MiB limit for raw artifact uploads.
const DefaultMaxContentBytes int64 = 64 * 1024 * 1024

// MaxFilenameLength and MaxMediaTypeLength bound untrusted multipart headers.
const (
	MaxFilenameLength  = 255
	MaxMediaTypeLength = 128
)

// ContentMetadata records metadata derived from raw artifact content bytes.
type ContentMetadata struct {
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
	Filename  string `json:"filename,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

// ArtifactInput represents the submitted artifact for evaluation.
// Exactly one of PURL, Digest, or Content must be supplied (exclusive artifact types).
type ArtifactInput struct {
	PURL        string           `json:"purl,omitempty"`
	Digest      string           `json:"digest,omitempty"`
	Content     []byte           `json:"-"`
	Filename    string           `json:"-"`
	MediaType   string           `json:"-"`
	ContentMeta *ContentMetadata `json:"content,omitempty"`
}

// ValidateAndNormalizeArtifact validates the submitted artifact fields and
// enforces that exactly one artifact form (purl, digest, or content) is
// supplied. It fails closed wrapping ErrValidation if zero or multiple
// artifact types are provided, or if any field is malformed.
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

	providedCount := 0
	if out.PURL != "" {
		providedCount++
	}
	if out.Digest != "" {
		providedCount++
	}
	if len(out.Content) > 0 {
		providedCount++
	}
	if providedCount != 1 {
		return ArtifactInput{}, fmt.Errorf("%w: artifact requires exactly one of purl, digest, or content", ErrValidation)
	}

	if len(out.Content) == 0 && (out.Filename != "" || out.MediaType != "") {
		return ArtifactInput{}, fmt.Errorf("%w: filename and mediaType are only permitted with content uploads", ErrValidation)
	}

	if out.PURL != "" {
		canonical, err := CanonicalPurl(out.PURL)
		if err != nil {
			return ArtifactInput{}, fmt.Errorf("%w: invalid purl: %w", ErrValidation, err)
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
			return ArtifactInput{}, fmt.Errorf("%w: artifact content size %d exceeds maximum %d bytes", ErrValidation, len(out.Content), maxBytes)
		}
		cleanFilename, err := ValidateFilename(out.Filename)
		if err != nil {
			return ArtifactInput{}, err
		}
		cleanMediaType, err := ValidateMediaType(out.MediaType)
		if err != nil {
			return ArtifactInput{}, err
		}

		sum256 := sha256.Sum256(out.Content)
		hex256 := hex.EncodeToString(sum256[:])
		sizeBytes := int64(len(out.Content))

		// Release raw byte slice reference once metadata is computed so
		// persisted/in-memory Submission records do not retain large blobs.
		out.Content = nil
		out.Filename = cleanFilename
		out.MediaType = cleanMediaType
		out.ContentMeta = &ContentMetadata{
			SHA256:    hex256,
			SizeBytes: sizeBytes,
			Filename:  cleanFilename,
			MediaType: cleanMediaType,
		}
	}

	return out, nil
}

// ValidateFilename validates an untrusted multipart upload filename, rejecting
// control characters, null bytes, path separators, traversal names, and
// oversized strings (failing closed).
func ValidateFilename(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if len(name) > MaxFilenameLength {
		return "", fmt.Errorf("%w: invalid filename: exceeds maximum length of %d bytes", ErrValidation, MaxFilenameLength)
	}
	if name == "." || name == ".." {
		return "", fmt.Errorf("%w: invalid filename %q", ErrValidation, name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c == 0x7f || c == '/' || c == '\\' {
			return "", fmt.Errorf("%w: invalid filename: contains forbidden character", ErrValidation)
		}
	}
	return name, nil
}

// ValidateMediaType validates and canonicalizes an untrusted multipart
// Content-Type header value, failing closed on malformed MIME types or control
// characters.
func ValidateMediaType(mt string) (string, error) {
	if mt == "" {
		return "", nil
	}
	if len(mt) > MaxMediaTypeLength {
		return "", fmt.Errorf("%w: invalid mediaType: exceeds maximum length of %d bytes", ErrValidation, MaxMediaTypeLength)
	}
	for i := 0; i < len(mt); i++ {
		c := mt[i]
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%w: invalid mediaType: contains control character", ErrValidation)
		}
	}
	mediaType, _, err := mime.ParseMediaType(mt)
	if err != nil || mediaType == "" {
		return "", fmt.Errorf("%w: invalid mediaType %q", ErrValidation, mt)
	}
	return mediaType, nil
}

// ValidateDigest verifies that a digest string uses a supported algorithm
// prefix (sha256, sha384, sha512) and valid hexadecimal characters.
func ValidateDigest(d string) error {
	parts := strings.SplitN(strings.ToLower(strings.TrimSpace(d)), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: invalid digest %q: expected <algorithm>:<hex>", ErrValidation, d)
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
		return fmt.Errorf("%w: unsupported digest algorithm %q", ErrValidation, alg)
	}
	if len(val) != expectedLen {
		return fmt.Errorf("%w: invalid %s digest length: got %d hex chars, want %d", ErrValidation, alg, len(val), expectedLen)
	}
	if _, err := hex.DecodeString(val); err != nil {
		return fmt.Errorf("%w: invalid digest hex in %q: %w", ErrValidation, d, err)
	}
	return nil
}
