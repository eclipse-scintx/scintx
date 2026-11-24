// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// NewID generates a readable, unique identifier with the given prefix.
// For example, NewID("submission") produces "submission-<hex>".
func NewID(prefix string) string {
	return prefix + "-" + RandHex()
}

// RandHex returns a random hex identifier fragment with a short timestamp suffix.
// It falls back to the current clock if the cryptographic random reader fails.
func RandHex() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("000000000000-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
