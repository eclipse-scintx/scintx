// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package policy

import (
	"fmt"
	"sort"

	"github.com/yeeth-security/scintx/api"
)

// Evaluate runs the Policy Engine on an immutable AggregateReport and produces a PolicyReport (#68, #72, #75).
// Evaluation is deterministic and read-only.
func Evaluate(pol *api.PolicyDefinition, agg *api.AggregateReport) (*api.PolicyReport, error) {
	if err := Validate(pol); err != nil {
		return nil, err
	}
	if agg == nil {
		return nil, fmt.Errorf("aggregate report is required")
	}

	capCoverage := computeCapabilityCoverage(pol.Capabilities, agg)
	evidenceStatus := computeOverallEvidenceStatus(pol.Capabilities, capCoverage, agg)

	violations, unresolvedViolations, err := evaluateRules(pol.Violations, agg, capCoverage)
	if err != nil {
		return nil, err
	}
	annotations, _, err := evaluateRules(pol.Annotations, agg, capCoverage)
	if err != nil {
		return nil, err
	}

	// Determine the Policy Verdict (#68, #72, #75):
	// - Any triggered violation -> "violated"
	// - No triggered violations, but one or more violation rules lack completed coverage -> "undetermined"
	// - All violation rules conclusively evaluated with zero matches -> "satisfied"
	verdict := api.VerdictSatisfied
	if len(violations) > 0 {
		verdict = api.VerdictViolated
	} else if len(unresolvedViolations) > 0 {
		verdict = api.VerdictUndetermined
	}

	return &api.PolicyReport{
		SchemaVersion:     api.SchemaVersionV1,
		ID:                api.NewID("policy-report"),
		SubmissionID:      agg.Submission.ID,
		AggregateReportID: agg.ID,
		Policy: api.PolicyReportRef{
			ID:      pol.ID,
			Version: pol.Version,
		},
		Artifact:         agg.Artifact,
		EvaluationStatus: api.EvaluationCompleted,
		EvidenceStatus:   evidenceStatus,
		PolicyVerdict:    verdict,
		UnresolvedRules:  unresolvedViolations,
		Violations:       violations,
		Annotations:      annotations,
	}, nil
}

func evaluateRules(
	rules map[string]api.PolicyRule,
	agg *api.AggregateReport,
	capCoverage map[api.Capability]api.CapabilityStatus,
) ([]api.TriggeredRule, []string, error) {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	triggered := make([]api.TriggeredRule, 0)
	var unresolved []string

	for _, id := range ids {
		rule := rules[id]
		expr, err := parseExpression(rule.When)
		if err != nil {
			return nil, nil, err
		}
		matches, isUnresolved := evalSingleRule(expr, agg, capCoverage)
		if len(matches) > 0 {
			triggered = append(triggered, api.TriggeredRule{
				ID:          id,
				Description: rule.Description,
				Matches:     matches,
			})
		} else if isUnresolved {
			unresolved = append(unresolved, id)
		}
	}
	return triggered, unresolved, nil
}

func evalSingleRule(
	expr *parsedExpr,
	agg *api.AggregateReport,
	capCoverage map[api.Capability]api.CapabilityStatus,
) ([]api.RuleMatch, bool) {
	switch expr.target {
	case "findings":
		var matches []api.RuleMatch
		for _, rep := range agg.ProviderReports {
			capRep, ok := rep.Capabilities[expr.capability]
			if !ok || capRep.Status == api.CapabilityStatusUnavailable {
				continue
			}
			for _, f := range capRep.Findings {
				if matchFindingField(f, expr.field, expr.op, expr.value) {
					targetArt := agg.Artifact
					if f.Artifact != nil {
						targetArt = *f.Artifact
					}
					matches = append(matches, api.RuleMatch{
						Artifact:       targetArt,
						DependencyPath: f.DependencyPath,
						Evidence: []api.RuleEvidence{{
							Type:             "finding",
							Capability:       expr.capability,
							Provider:         rep.Provider,
							ProviderRunID:    rep.ProviderRunID,
							ProviderReportID: rep.ID,
							FindingID:        f.ID,
						}},
					})
				}
			}
		}
		status := capCoverage[expr.capability]
		unresolved := len(matches) == 0 && status != api.CapabilityStatusCompleted
		return matches, unresolved

	case "providerRuns":
		var matches []api.RuleMatch
		for _, run := range agg.ProviderRuns {
			var actual string
			if expr.field == "status" {
				actual = string(run.Status)
			} else if expr.field == "error.code" && run.Error != nil {
				actual = string(run.Error.Code)
			}
			if compareString(actual, expr.op, expr.value) {
				ev := api.RuleEvidence{
					Type:          "providerRun",
					Provider:      run.Provider,
					ProviderRunID: run.ID,
					Status:        run.Status,
				}
				if run.Error != nil {
					ev.ErrorCode = run.Error.Code
				}
				matches = append(matches, api.RuleMatch{
					Artifact: agg.Artifact,
					Evidence: []api.RuleEvidence{ev},
				})
			}
		}
		return matches, false

	case "providers":
		var matches []api.RuleMatch
		for _, p := range agg.Providers {
			if p.Slug == expr.value && !p.Available {
				matches = append(matches, api.RuleMatch{
					Artifact: agg.Artifact,
					Evidence: []api.RuleEvidence{{Type: "provider", Provider: p.Slug}},
				})
			}
		}
		return matches, false
	}
	return nil, false
}

func computeCapabilityCoverage(declared []api.Capability, agg *api.AggregateReport) map[api.Capability]api.CapabilityStatus {
	cov := make(map[api.Capability]api.CapabilityStatus, len(declared))
	for _, capName := range declared {
		hasCompleted, hasPartial := false, false
		for _, rep := range agg.ProviderReports {
			if cr, ok := rep.Capabilities[capName]; ok {
				if cr.Status == api.CapabilityStatusCompleted {
					hasCompleted = true
				} else if cr.Status == api.CapabilityStatusPartial {
					hasPartial = true
				}
			}
		}
		switch {
		case hasCompleted:
			cov[capName] = api.CapabilityStatusCompleted
		case hasPartial:
			cov[capName] = api.CapabilityStatusPartial
		default:
			cov[capName] = api.CapabilityStatusUnavailable
		}
	}
	return cov
}

func computeOverallEvidenceStatus(
	declared []api.Capability,
	cov map[api.Capability]api.CapabilityStatus,
	agg *api.AggregateReport,
) api.EvidenceStatus {
	if len(agg.ProviderRuns) == 0 {
		return api.EvidenceUnavailable
	}
	allRunsCompleted := true
	for _, r := range agg.ProviderRuns {
		if r.Status != api.RunStatusCompleted {
			allRunsCompleted = false
			break
		}
	}
	allCapsCompleted := true
	for _, c := range declared {
		if cov[c] != api.CapabilityStatusCompleted {
			allCapsCompleted = false
			break
		}
	}
	if allRunsCompleted && allCapsCompleted {
		return api.EvidenceComplete
	}
	if len(agg.ProviderReports) > 0 {
		return api.EvidencePartial
	}
	return api.EvidenceUnavailable
}
