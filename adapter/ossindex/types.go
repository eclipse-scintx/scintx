// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package ossindex

// This file defines the JSON request and response wire structures for Sonatype
// Guide's OSS Index Compatibility API (POST /api/v3/component-report) (#95, #98).

// ComponentReportRequest is the JSON request body sent to
// POST /api/v3/component-report.
type ComponentReportRequest struct {
	Coordinates []string `json:"coordinates"`
}

// ComponentReport represents the vulnerability assessment returned by OSS Index
// for a single requested package coordinate.
//
// Note: Under the Sonatype Guide OSS Index Compatibility API, the component
// Description field may be omitted by upstream, and an unmatched coordinate may
// return an empty Vulnerabilities slice (#95).
type ComponentReport struct {
	Coordinates     string          `json:"coordinates"`
	Description     string          `json:"description,omitempty"`
	Reference       string          `json:"reference,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a single vulnerability entry inside a
// ComponentReport returned by POST /api/v3/component-report (#95, #98).
type Vulnerability struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"displayName,omitempty"`
	Title              string   `json:"title,omitempty"`
	Description        string   `json:"description,omitempty"`
	CVSSScore          *float64 `json:"cvssScore,omitempty"`
	CVSSVector         string   `json:"cvssVector,omitempty"`
	CWE                string   `json:"cwe,omitempty"`
	CVE                string   `json:"cve,omitempty"`
	Reference          string   `json:"reference,omitempty"`
	VersionRanges      []string `json:"versionRanges,omitempty"`
	ExternalReferences []string `json:"externalReferences,omitempty"`
}
