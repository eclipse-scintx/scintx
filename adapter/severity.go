// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"math"
	"strconv"
	"strings"
)

// This file provides shared severity normalization and string deduplication
// helpers so all provider adapters map upstream severity labels, numeric CVSS
// base scores (0.0–10.0), and CVSS v3/v4 vector strings onto the standardized
// SCINTX Severity scale (#72, #98).

// ParseSeverityLabel maps common upstream severity and Linux distribution
// urgency strings ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW",
// "NEGLIGIBLE", "UNIMPORTANT", "INFO", "INFORMATIONAL", "NONE") to Severity.
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
	case "INFO", "INFORMATIONAL", "NONE", "NEGLIGIBLE", "UNIMPORTANT":
		return SeverityInfo, true
	default:
		return "", false
	}
}

// SeverityFromCVSSScore maps a numeric CVSS base score string in [0.0, 10.0],
// a CVSS v3.0/v3.1/v4.0 vector string, or a qualitative label to Severity.
func SeverityFromCVSSScore(score string) (Severity, bool) {
	trimmed := strings.TrimSpace(score)
	if val, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return SeverityFromCVSSFloat(val)
	}
	if strings.HasPrefix(trimmed, "CVSS:3.0/") || strings.HasPrefix(trimmed, "CVSS:3.1/") {
		if base, ok := cvssV3BaseScore(trimmed); ok {
			return SeverityFromCVSSFloat(base)
		}
	}
	if strings.HasPrefix(trimmed, "CVSS:4.0/") {
		return severityFromCVSSV4Vector(trimmed)
	}
	return ParseSeverityLabel(trimmed)
}

// SeverityFromCVSSFloat maps a numeric CVSS base score in [0.0, 10.0] to the
// standard CVSS v3/v4 qualitative severity ratings.
func SeverityFromCVSSFloat(val float64) (Severity, bool) {
	if val < 0 || val > 10 {
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

// DeduplicateStrings trims whitespace from each entry, drops empty strings,
// and returns a slice containing the unique values in first-seen order (#98).
func DeduplicateStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

// cvssV3BaseScore computes the standard FIRST.org CVSS v3.0/v3.1 base score
// from a vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
func cvssV3BaseScore(vector string) (float64, bool) {
	m := parseCVSSVector(vector)
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cVal, ok4 := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[m["C"]]
	iVal, ok5 := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[m["I"]]
	aVal, ok6 := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}[m["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scope == "C" {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scope == "C" {
			pr = 0.50
		}
	default:
		return 0, false
	}

	iss := 1.0 - (1.0-cVal)*(1.0-iVal)*(1.0-aVal)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0.0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	raw := impact + exploitability
	if scope == "C" {
		raw = 1.08 * raw
	}
	if raw > 10.0 {
		raw = 10.0
	}
	return math.Ceil(math.Round(raw*100000.0)/10000.0) / 10.0, true
}

// severityFromCVSSV4Vector derives a qualitative Severity rating from a CVSS v4.0
// vector string based on vulnerable/subsequent system impact and exploitability.
func severityFromCVSSV4Vector(vector string) (Severity, bool) {
	m := parseCVSSVector(vector)
	vc, vi, va := m["VC"], m["VI"], m["VA"]
	sc, si, sa := m["SC"], m["SI"], m["SA"]
	if vc == "" || vi == "" || va == "" {
		return "", false
	}
	hasHigh := vc == "H" || vi == "H" || va == "H" || sc == "H" || si == "H" || sa == "H"
	hasLow := vc == "L" || vi == "L" || va == "L" || sc == "L" || si == "L" || sa == "L"
	if !hasHigh && !hasLow {
		return SeverityInfo, true
	}
	easyExploit := m["AV"] == "N" && m["AC"] == "L" && (m["AT"] == "" || m["AT"] == "N") && m["PR"] == "N" && m["UI"] == "N"
	if hasHigh {
		if easyExploit && (vc == "H" || vi == "H" || va == "H") {
			return SeverityCritical, true
		}
		return SeverityHigh, true
	}
	if m["AV"] == "N" && m["AC"] == "L" {
		return SeverityMedium, true
	}
	return SeverityLow, true
}

func parseCVSSVector(vector string) map[string]string {
	parts := strings.Split(vector, "/")
	out := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(p, ":"); ok {
			out[k] = v
		}
	}
	return out
}
