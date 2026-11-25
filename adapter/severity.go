// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"strconv"
	"strings"
)

// This file provides shared severity normalization helpers so all provider
// adapters map upstream severity labels and numeric CVSS base scores (0.0–10.0)
// onto the standardized SCINTX Severity scale using identical thresholds (#72, #98).

// ParseSeverityLabel maps common upstream severity strings ("CRITICAL", "HIGH",
// "MODERATE", "MEDIUM", "LOW", "INFO", "INFORMATIONAL", "NONE") to Severity.
func ParseSeverityLabel(raw string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return SeverityCritical, true
	case "HIGH":
		return SeverityHigh, true
	case "MODERATE", "MEDIUM":
		return SeverityMedium, true
	case "LOW":
		return SeverityLow, true
	case "INFO", "INFORMATIONAL", "NONE":
		return SeverityInfo, true
	default:
		return "", false
	}
}

// SeverityFromCVSSScore maps a numeric CVSS base score string in [0.0, 10.0]
// to the standard CVSS v3/v4 qualitative severity ratings.
func SeverityFromCVSSScore(score string) (Severity, bool) {
	val, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil || val < 0 || val > 10 {
		return "", false
	}
	switch {
	case val >= 9.0:
		return SeverityCritical, true
	case val >= 7.0:
		return SeverityHigh, true
	case val >= 4.0:
		return SeverityMedium, true
	case val > 0.0:
		return SeverityLow, true
	default:
		return SeverityInfo, true
	}
}
