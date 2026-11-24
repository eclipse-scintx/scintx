// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package osv

import (
	"encoding/json"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// buildOSVResult converts OSV vulnerability records into a normalized SCINTX EvaluationResult (#70, #72).
func buildOSVResult(
	req api.EvaluationRequest,
	vulns []osvVulnerability,
	rawPages []json.RawMessage,
) (*api.EvaluationResult, error) {
	vulnFindings := make([]api.Finding, 0)
	threatFindings := make([]api.Finding, 0)

	for _, v := range vulns {
		if v.ID == "" {
			return nil, &api.AdapterError{
				Code:      api.ErrMalformedResponse,
				Message:   "OSV advisory record is missing required id field",
				Retryable: false,
			}
		}

		isMalware := strings.HasPrefix(v.ID, "MAL-")
		findingType := "vulnerability"
		if isMalware {
			findingType = "malware"
		}

		finding := api.Finding{
			ID:          v.ID,
			Type:        findingType,
			Severity:    extractSeverity(v),
			Title:       v.Summary,
			Description: v.Details,
			Artifact: &api.ArtifactInput{
				PURL: req.Artifact.PURL,
			},
			Identifiers: append([]string{v.ID}, v.Aliases...),
		}

		if isMalware {
			threatFindings = append(threatFindings, finding)
		} else {
			vulnFindings = append(vulnFindings, finding)
		}
	}

	rawEvidence, _ := json.Marshal(map[string]any{
		"pages": rawPages,
		"count": len(vulns),
	})

	report := api.ProviderReport{
		SchemaVersion:  api.SchemaVersionV1,
		ProviderRunID:  req.ProviderRunID,
		Provider:       "osv",
		AdapterVersion: "1.0.0",
		Capabilities: map[api.Capability]api.CapabilityReport{
			api.CapabilityVulnerabilities: {
				Status:   api.CapabilityStatusCompleted,
				Checks:   []api.CheckResult{{ID: "known-vulnerabilities", Status: api.CapabilityStatusCompleted}},
				Findings: vulnFindings,
			},
			api.CapabilityThreats: {
				Status:   api.CapabilityStatusCompleted,
				Checks:   []api.CheckResult{{ID: "malware", Status: api.CapabilityStatusCompleted}},
				Findings: threatFindings,
			},
		},
	}

	return &api.EvaluationResult{
		Report:      report,
		RawEvidence: rawEvidence,
	}, nil
}

// extractSeverity maps OSV database_specific.severity or MAL-* advisories to SCINTX Severity.
func extractSeverity(v osvVulnerability) api.Severity {
	if strings.HasPrefix(v.ID, "MAL-") {
		return api.SeverityCritical
	}
	if raw, ok := v.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(raw) {
		case "CRITICAL":
			return api.SeverityCritical
		case "HIGH":
			return api.SeverityHigh
		case "MODERATE", "MEDIUM":
			return api.SeverityMedium
		case "LOW":
			return api.SeverityLow
		}
	}
	return api.SeverityUnknown
}

// parseVSCodeExtensionPURL extracts "<publisher>.<name>" and "<version>" from
// "pkg:vscode-extension/<publisher>/<name>@<version>" (#43, #70).
func parseVSCodeExtensionPURL(purl string) (extName, version string, ok bool) {
	rest := strings.TrimPrefix(purl, "pkg:vscode-extension/")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if at := strings.Index(rest, "@"); at >= 0 {
		version = rest[at+1:]
		rest = rest[:at]
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0] + "." + parts[1], version, true
}

// offlineFixtureForPURL returns deterministic OSV advisories when SCINTX_DEMO_FIXTURES=1 (#41).
// This enables offline container and quickstart demonstrations without live network calls.
func offlineFixtureForPURL(purl string) ([]osvVulnerability, []json.RawMessage) {
	switch purl {
	case "pkg:npm/lodash@4.17.20", "pkg:npm/example@1.2.3":
		vulns := []osvVulnerability{{
			ID:      "GHSA-35jh-r3h4-6jhm",
			Summary: "Command Injection in lodash",
			Details: "lodash versions prior to 4.17.21 are vulnerable to command injection.",
			Aliases: []string{"CVE-2021-23337"},
			DatabaseSpecific: map[string]any{
				"severity": "CRITICAL",
			},
		}}
		raw, _ := json.Marshal(osvQueryResponse{Vulns: vulns})
		return vulns, []json.RawMessage{raw}
	case "pkg:vscode-extension/evil-pub/malicious-ext@1.0.0":
		vulns := []osvVulnerability{{
			ID:      "MAL-2026-0001",
			Summary: "Malicious VS Code extension exfiltrates credentials",
			Details: "Extension contains known malware payload.",
		}}
		raw, _ := json.Marshal(osvQueryResponse{Vulns: vulns})
		return vulns, []json.RawMessage{raw}
	default:
		raw := json.RawMessage(`{"vulns":[]}`)
		return nil, []json.RawMessage{raw}
	}
}
