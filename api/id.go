// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

var submissionIDRe = regexp.MustCompile(`^submission-[0-9a-f]{12}$`)

// NewID generates a readable, unique identifier with the given prefix.
// For example, NewID("submission") produces "submission-<12 hex chars>".
func NewID(prefix string) string {
	return prefix + "-" + RandHex()
}

// RandHex returns a 12-character cryptographic random hex string.
// It panics if the OS cryptographic random source fails rather than falling
// back to a predictable timestamp (fail-closed).
func RandHex() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// IsValidSubmissionID reports whether id matches the canonical
// "submission-<12 lowercase hex chars>" identifier format.
func IsValidSubmissionID(id string) bool {
	return submissionIDRe.MatchString(id)
}
