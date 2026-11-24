// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

// submissionIDRe matches the canonical submission identifier format:
// "submission-" followed by 32 lowercase hexadecimal characters (128 bits of
// cryptographic entropy). Using 128 bits instead of 48 bits eliminates the
// birthday-bound collision risk across high-volume submission streams.
var submissionIDRe = regexp.MustCompile(`^submission-[0-9a-f]{32}$`)

// NewID generates a readable, unique identifier with the given prefix.
// For example, NewID("submission") produces "submission-<32 hex chars>".
func NewID(prefix string) string {
	return prefix + "-" + RandHex()
}

// RandHex returns a 32-character (128-bit) cryptographic random hex string.
// It panics if the OS cryptographic random source fails rather than falling
// back to a predictable timestamp (fail-closed).
func RandHex() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// IsValidSubmissionID reports whether id matches the canonical
// "submission-<32 lowercase hex chars>" identifier format.
func IsValidSubmissionID(id string) bool {
	return submissionIDRe.MatchString(id)
}
