// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

// This file defines the wire structures used by the OSV.dev HTTP v1 API
// (POST /v1/query and GET /v1/vulns/{id}) so the adapter can query package
// advisories and retrieve full records for normalization (#94).

// QueryRequest is the JSON request body sent to POST /v1/query.
type QueryRequest struct {
	Package   *PackageQuery `json:"package,omitempty"`
	Version   string        `json:"version,omitempty"`
	PageToken string        `json:"page_token,omitempty"`
}

// PackageQuery identifies a package in an OSV query by PURL or by ecosystem and name.
type PackageQuery struct {
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
}

// QueryResponse is the JSON payload returned by POST /v1/query.
type QueryResponse struct {
	Vulns         []Vulnerability `json:"vulns"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

// Vulnerability represents an OSV schema record returned by POST /v1/query
// or GET /v1/vulns/{id}. It preserves identifiers, relationships, severity,
// affected package ranges, references, and database-specific metadata needed
// for SCINTX normalization (#94, #98).
type Vulnerability struct {
	SchemaVersion    string           `json:"schema_version,omitempty"`
	ID               string           `json:"id"`
	Summary          string           `json:"summary,omitempty"`
	Details          string           `json:"details,omitempty"`
	Aliases          []string         `json:"aliases,omitempty"`
	Related          []string         `json:"related,omitempty"`
	Upstream         []string         `json:"upstream,omitempty"`
	Published        string           `json:"published,omitempty"`
	Modified         string           `json:"modified,omitempty"`
	Withdrawn        string           `json:"withdrawn,omitempty"`
	Severity         []SeverityEntry  `json:"severity,omitempty"`
	Affected         []AffectedEntry  `json:"affected,omitempty"`
	References       []ReferenceEntry `json:"references,omitempty"`
	DatabaseSpecific map[string]any   `json:"database_specific,omitempty"`
}

// SeverityEntry represents an entry in an OSV record's top-level or package-level
// severity array (for example, CVSS_V3 or CVSS_V4 score strings).
type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// AffectedEntry describes one package and version range affected by an OSV advisory.
type AffectedEntry struct {
	Package           *PackageQuery   `json:"package,omitempty"`
	Severity          []SeverityEntry `json:"severity,omitempty"`
	Ranges            []RangeEntry    `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific map[string]any  `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any  `json:"database_specific,omitempty"`
}

// RangeEntry describes a version range (SEMVER, ECOSYSTEM, or GIT) in an OSV record.
type RangeEntry struct {
	Type   string       `json:"type"`
	Repo   string       `json:"repo,omitempty"`
	Events []EventEntry `json:"events,omitempty"`
}

// EventEntry marks a version boundary (introduced, fixed, last_affected, limit).
type EventEntry struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// ReferenceEntry holds an external URL (ADVISORY, WEB, FIX, REPORT, PACKAGE) on an OSV record.
type ReferenceEntry struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// isStubRecord reports whether a Vulnerability entry returned by a query only
// contains minimal index fields (such as id and modified) and therefore needs
// a follow-up GET /v1/vulns/{id} call to retrieve the full record before
// normalization (#94).
func isStubRecord(v Vulnerability) bool {
	return v.Summary == "" &&
		v.Details == "" &&
		len(v.Aliases) == 0 &&
		len(v.Severity) == 0 &&
		len(v.Affected) == 0 &&
		len(v.References) == 0 &&
		len(v.DatabaseSpecific) == 0
}
