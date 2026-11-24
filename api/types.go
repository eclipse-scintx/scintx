// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"encoding/hex"
	"errors"
	"fmt"
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

// ArtifactInput represents the submitted artifact for evaluation.
// Exactly one of PURL, Digest, or an uploaded file must be supplied
// (exclusive artifact types).
type ArtifactInput struct {
	PURL   string `json:"purl,omitempty"`
	Digest string `json:"digest,omitempty"`

	// Upload holds what the server measured while streaming an uploaded file
	// (see HashContent). It is tagged json:"-" so a client can never set it.
	//
	// It replaces the old Content []byte, Filename, and MediaType fields. Those
	// forced the whole upload into memory just to hash it. Only the hash and
	// size were ever kept, so the bytes are no longer buffered at all.
	Upload *ContentMetadata `json:"-"`

	// ContentMeta is the validated, public form of Upload. Only the server
	// fills it in. It keeps its JSON tag because stored submissions are read
	// back through it, but it is rejected when a client sends it.
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
	// A client must not hand us "content" metadata in JSON. The server
	// computes it from real bytes. Before this check the object was silently
	// dropped, so a request could look like it carried content when it did not.
	if in.ContentMeta != nil {
		return ArtifactInput{}, fmt.Errorf("%w: content metadata is computed by the server; upload the file with multipart/form-data", ErrValidation)
	}
	out := ArtifactInput{
		PURL:   strings.TrimSpace(in.PURL),
		Digest: strings.ToLower(strings.TrimSpace(in.Digest)),
	}

	providedCount := 0
	if out.PURL != "" {
		providedCount++
	}
	if out.Digest != "" {
		providedCount++
	}
	if in.Upload != nil {
		providedCount++
	}
	if providedCount != 1 {
		return ArtifactInput{}, fmt.Errorf("%w: artifact requires exactly one of purl, digest, or content", ErrValidation)
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

	if in.Upload != nil {
		upload := *in.Upload
		upload.Filename = strings.TrimSpace(upload.Filename)
		upload.MediaType = strings.TrimSpace(upload.MediaType)
		meta, err := validateUpload(upload, maxBytes)
		if err != nil {
			return ArtifactInput{}, err
		}
		// Only the clean public metadata leaves this function. out.Upload
		// stays nil, so the raw measured values are not carried any further.
		out.ContentMeta = meta
	}

	return out, nil
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
