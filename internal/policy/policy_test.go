// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package policy_test

import (
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/policy"
)

const sampleBaselineYAML = `schemaVersion: "1"
id: baseline-security
name: Baseline Security
version: 1.0.0
description: Basic supply chain security checks
capabilities:
  - threats
  - vulnerabilities
  - health
  - licenses
violations:
  known-malware:
    description: Artifact contains known malware
    when: threats.findings.any(f => f.type == "malware")
  critical-vulnerability:
    description: Artifact contains critical vulnerabilities
    when: vulnerabilities.findings.any(f => f.severity == "critical")
  provider-run-incomplete:
    description: A selected provider run did not complete successfully
    when: aggregateReport.providerRuns.any(r => r.status != "completed")
annotations:
  needs-review:
    description: Artifact has high-severity findings
    when: vulnerabilities.findings.any(f => f.severity == "high")
evaluationDeadline: 10m
`

func TestValidateRejectsUndeclaredCapability(t *testing.T) {
	badYAML := `schemaVersion: "1"
id: bad-policy
name: Bad Policy
version: 1.0.0
capabilities:
  - vulnerabilities
violations:
  malware-check:
    description: References threats without declaring it
    when: threats.findings.any(f => f.type == "malware")
evaluationDeadline: 30s
`
	if _, err := policy.ParseAndValidate([]byte(badYAML)); err == nil {
		t.Fatal("expected validation failure for undeclared capability reference")
	}
}

func TestEvaluateViolatedAndUndeterminedAndSatisfied(t *testing.T) {
	pol, err := policy.ParseAndValidate([]byte(sampleBaselineYAML))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	reportID := "report-001"
	// 1. Clean completed evidence for threats and vulnerabilities -> satisfied.
	cleanAgg := &api.AggregateReport{
		SchemaVersion: "1",
		ID:            "agg-1",
		Submission:    api.SubmissionRef{ID: "sub-1"},
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"},
		ProviderRuns: []api.ProviderRun{
			{ID: "run-1", Provider: "osv", Status: api.RunStatusCompleted, ReportID: &reportID},
		},
		ProviderReports: []api.ProviderReport{
			{
				ID:            reportID,
				ProviderRunID: "run-1",
				Provider:      "osv",
				Capabilities: map[api.Capability]api.CapabilityReport{
					api.CapabilityThreats:         {Status: api.CapabilityStatusCompleted, Findings: []api.Finding{}},
					api.CapabilityVulnerabilities: {Status: api.CapabilityStatusCompleted, Findings: []api.Finding{}},
				},
			},
		},
	}
	rep, err := policy.Evaluate(pol, cleanAgg)
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}
	if rep.PolicyVerdict != api.VerdictSatisfied {
		t.Fatalf("got verdict %q, want satisfied", rep.PolicyVerdict)
	}

	// 2. Critical vulnerability + incomplete run -> violated (#68).
	vulnAgg := &api.AggregateReport{
		SchemaVersion: "1",
		ID:            "agg-2",
		Submission:    api.SubmissionRef{ID: "sub-2"},
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/example@1.2.3"},
		ProviderRuns: []api.ProviderRun{
			{ID: "run-1", Provider: "osv", Status: api.RunStatusCompleted, ReportID: &reportID},
			{ID: "run-2", Provider: "ossindex", Status: api.RunStatusIncomplete},
		},
		ProviderReports: []api.ProviderReport{
			{
				ID:            reportID,
				ProviderRunID: "run-1",
				Provider:      "osv",
				Capabilities: map[api.Capability]api.CapabilityReport{
					api.CapabilityVulnerabilities: {
						Status: api.CapabilityStatusCompleted,
						Findings: []api.Finding{{
							ID:       "finding-001",
							Type:     "vulnerability",
							Severity: api.SeverityCritical,
							Title:    "Critical CVE",
						}},
					},
				},
			},
		},
	}
	rep2, err := policy.Evaluate(pol, vulnAgg)
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}
	if rep2.PolicyVerdict != api.VerdictViolated || len(rep2.Violations) != 2 {
		t.Fatalf("got verdict=%q violations=%d, want violated with 2 violations", rep2.PolicyVerdict, len(rep2.Violations))
	}

	// 3. Policy without provider-run-incomplete when evidence is missing -> undetermined (#68, #72).
	lenientYAML := `schemaVersion: "1"
id: lenient
name: Lenient
version: 1.0.0
capabilities:
  - vulnerabilities
violations:
  critical-vulnerability:
    description: Critical vulnerability
    when: vulnerabilities.findings.any(f => f.severity == "critical")
evaluationDeadline: 30s
`
	lenientPol, err := policy.ParseAndValidate([]byte(lenientYAML))
	if err != nil {
		t.Fatal(err)
	}
	missingEvidenceAgg := &api.AggregateReport{
		SchemaVersion: "1",
		ID:            "agg-3",
		Submission:    api.SubmissionRef{ID: "sub-3"},
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/example@1.2.3"},
		ProviderRuns:  []api.ProviderRun{{ID: "run-1", Provider: "osv", Status: api.RunStatusFailed}},
	}
	rep3, err := policy.Evaluate(lenientPol, missingEvidenceAgg)
	if err != nil {
		t.Fatal(err)
	}
	if rep3.PolicyVerdict != api.VerdictUndetermined {
		t.Fatalf("got verdict %q, want undetermined when required capability evidence is missing", rep3.PolicyVerdict)
	}
}
