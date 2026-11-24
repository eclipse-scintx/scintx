// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// SchemaVersionV1 identifies version 1 of the SCINTX JSON and YAML schemas (#68, #69).
const SchemaVersionV1 = "1"

// Capability represents a first-class SCINTX analysis category (#68, #71).
// Policies declare these capabilities at the top level to drive provider selection.
type Capability string

const (
	CapabilityVulnerabilities Capability = "vulnerabilities"
	CapabilityThreats         Capability = "threats"
	CapabilityLicenses        Capability = "licenses"
	CapabilityHealth          Capability = "health"
	CapabilityIntegrity       Capability = "integrity"
	CapabilityDependencies    Capability = "dependencies"
)

// ValidCapabilities lists all recognized SCINTX capabilities.
var ValidCapabilities = map[Capability]bool{
	CapabilityVulnerabilities: true,
	CapabilityThreats:         true,
	CapabilityLicenses:        true,
	CapabilityHealth:          true,
	CapabilityIntegrity:       true,
	CapabilityDependencies:    true,
}

// NormalizeCapability maps singular aliases (such as "vulnerability" from #68 examples)
// to their canonical plural capability name ("vulnerabilities").
func NormalizeCapability(raw string) Capability {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "vulnerability" {
		return CapabilityVulnerabilities
	}
	return Capability(trimmed)
}

// ArtifactInputType identifies how a consumer supplied an artifact (#68, #71).
type ArtifactInputType string

const (
	InputTypePURL    ArtifactInputType = "purl"
	InputTypeDigest  ArtifactInputType = "digest"
	InputTypeContent ArtifactInputType = "content"
)

// Digest represents a cryptographic hash algorithm and hex value (#68).
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// ContentMetadata describes uploaded artifact bytes (#70).
type ContentMetadata struct {
	Filename  string `json:"filename,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
	SizeBytes int64  `json:"sizeBytes,omitempty"`
}

// ArtifactInput holds the normalized artifact identifiers and optional uploaded bytes (#68, #70).
// We preserve both the original consumer input and any gateway-derived digest or PURL.
type ArtifactInput struct {
	// PURL is a Package URL identifying the package by ecosystem, name, and version.
	PURL string `json:"purl,omitempty"`

	// Digest is a cryptographic hash of the artifact contents.
	Digest *Digest `json:"digest,omitempty"`

	// Filename is the uploaded file name when artifact bytes were supplied.
	Filename string `json:"filename,omitempty"`

	// MediaType is the MIME type of the uploaded artifact bytes.
	MediaType string `json:"mediaType,omitempty"`

	// ContentMeta holds size and file metadata for adapter inspection.
	ContentMeta *ContentMetadata `json:"contentMeta,omitempty"`

	// Content holds raw uploaded bytes in memory. It is never serialized into JSON reports.
	Content []byte `json:"-"`

	// OpenContent opens a reader for the uploaded bytes when Content is present.
	OpenContent func() (io.ReadCloser, error) `json:"-"`
}

var hexDigestRe = regexp.MustCompile(`^[a-fA-F0-9]{32,128}$`)

var supportedDigestAlgorithms = map[string]bool{
	"sha256": true,
	"sha384": true,
	"sha512": true,
}

// ValidateAndNormalizeArtifact validates the consumer's artifact input (#68).
// It checks PURL syntax, digest algorithm/hex formatting, and size limits.
// When raw bytes are uploaded, it calculates the SHA-256 digest and attempts
// to extract package coordinates from VSIX archives for Open VSX compatibility (#67).
func ValidateAndNormalizeArtifact(a *ArtifactInput, maxBytes int64) error {
	if a == nil {
		return fmt.Errorf("artifact is required")
	}
	hasPURL := strings.TrimSpace(a.PURL) != ""
	hasDigest := a.Digest != nil && (a.Digest.Algorithm != "" || a.Digest.Value != "")
	hasContent := len(a.Content) > 0

	if !hasPURL && !hasDigest && !hasContent {
		return fmt.Errorf("artifact must provide at least one of purl, digest, or content bytes")
	}

	if hasPURL {
		canonical, err := CanonicalPurl(strings.TrimSpace(a.PURL))
		if err != nil {
			return fmt.Errorf("invalid purl: %w", err)
		}
		a.PURL = canonical
	}

	if hasDigest {
		alg := strings.ToLower(strings.TrimSpace(a.Digest.Algorithm))
		val := strings.ToLower(strings.TrimSpace(a.Digest.Value))
		if !supportedDigestAlgorithms[alg] {
			return fmt.Errorf("unsupported digest algorithm %q (supported: sha256, sha384, sha512)", a.Digest.Algorithm)
		}
		if !hexDigestRe.MatchString(val) {
			return fmt.Errorf("invalid digest value for %s: must be hexadecimal", alg)
		}
		a.Digest = &Digest{Algorithm: alg, Value: val}
	}

	if hasContent {
		if maxBytes > 0 && int64(len(a.Content)) > maxBytes {
			return fmt.Errorf("artifact content size %d exceeds maximum %d bytes", len(a.Content), maxBytes)
		}
		sum := sha256.Sum256(a.Content)
		calculatedHex := hex.EncodeToString(sum[:])
		if hasDigest && a.Digest.Algorithm == "sha256" && a.Digest.Value != calculatedHex {
			return fmt.Errorf("supplied sha256 digest %s does not match uploaded content digest %s", a.Digest.Value, calculatedHex)
		}
		if !hasDigest {
			a.Digest = &Digest{Algorithm: "sha256", Value: calculatedHex}
		}
		a.ContentMeta = &ContentMetadata{
			Filename:  a.Filename,
			MediaType: a.MediaType,
			SizeBytes: int64(len(a.Content)),
		}
		rawBytes := a.Content
		a.OpenContent = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(rawBytes)), nil
		}
		// Derive a vscode-extension PURL if the uploaded content is a VSIX archive (#67).
		if a.PURL == "" {
			if derived := extractVSIXPURL(a.Content); derived != "" {
				a.PURL = derived
			}
		}
	}
	return nil
}
