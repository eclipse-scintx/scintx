// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
)

// This file holds everything about uploaded file content. It was split out of
// types.go to keep each file small.

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

// HashContent streams r through SHA-256 and returns the hex digest and size.
//
// It never holds the upload in memory. The old code read the whole file into
// a byte slice first (up to 64 MiB per request) and then threw it away, which
// made a cheap memory exhaustion attack possible.
//
// It reads at most maxBytes+1 bytes. The one extra byte is how it notices an
// oversized upload without reading all of it. An oversized upload returns an
// error that wraps ErrValidation. A plain read error is returned unwrapped.
func HashContent(r io.Reader, maxBytes int64) (string, int64, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxContentBytes
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size > maxBytes {
		return "", 0, fmt.Errorf("%w: artifact content exceeds maximum %d bytes", ErrValidation, maxBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// validateUpload checks the facts measured for an uploaded file and returns a
// clean copy. It fails closed on an empty or oversized file, on a digest that
// is not 64 hex characters, and on a bad filename or media type.
func validateUpload(up ContentMetadata, maxBytes int64) (*ContentMetadata, error) {
	if up.SizeBytes <= 0 {
		return nil, fmt.Errorf("%w: artifact content must not be empty", ErrValidation)
	}
	if up.SizeBytes > maxBytes {
		return nil, fmt.Errorf("%w: artifact content size %d exceeds maximum %d bytes", ErrValidation, up.SizeBytes, maxBytes)
	}
	if err := ValidateDigest("sha256:" + up.SHA256); err != nil {
		return nil, err
	}
	cleanFilename, err := ValidateFilename(up.Filename)
	if err != nil {
		return nil, err
	}
	cleanMediaType, err := ValidateMediaType(up.MediaType)
	if err != nil {
		return nil, err
	}
	return &ContentMetadata{
		SHA256:    up.SHA256,
		SizeBytes: up.SizeBytes,
		Filename:  cleanFilename,
		MediaType: cleanMediaType,
	}, nil
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
