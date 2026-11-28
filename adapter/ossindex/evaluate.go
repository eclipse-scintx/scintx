// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package ossindex

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file implements Evaluate and PURL coordinate validation/mapping for the
// OSS Index adapter against Sonatype Guide's Compatibility API (#95, #96, #98).

// Evaluate queries Sonatype Guide's OSS Index Compatibility API for the
// submitted PURL and normalizes any returned component vulnerabilities into a
// SCINTX ProviderReport.
func (a *Adapter) Evaluate(ctx context.Context, req adapter.EvaluationRequest) (*adapter.EvaluationResult, error) {
	canonicalPURL, queryCoord, err := validateAndMapPURL(req.Artifact.PURL)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(req.RequestedCapabilities, adapter.CapabilityVulnerabilities) {
		return nil, &adapter.AdapterError{
			Code:      adapter.ErrUnsupportedInput,
			Message:   "ossindex adapter does not support any of the requested capabilities",
			Retryable: false,
		}
	}

	reports, rawBody, err := a.queryComponentReport(ctx, queryCoord)
	if err != nil {
		return nil, err
	}

	findings := make([]adapter.Finding, 0)
	for _, comp := range reports {
		for _, v := range comp.Vulnerabilities {
			findings = append(findings, normalizeFinding(comp, v, canonicalPURL))
		}
	}

	capabilities := map[adapter.Capability]adapter.CapabilityReport{
		adapter.CapabilityVulnerabilities: adapter.NewCompletedCapabilityReport(
			adapter.CheckKnownVulnerabilities,
			findings,
		),
	}

	rawEvidence, _ := json.Marshal(map[string]any{
		adapter.EvidenceKeyComponents: json.RawMessage(rawBody),
		adapter.EvidenceKeyCount:      len(findings),
	})

	return &adapter.EvaluationResult{
		Report: adapter.ProviderReport{
			SchemaVersion:  adapter.SchemaVersionV1,
			ID:             adapter.NewProviderReportID(AdapterSlug, req.ProviderRunID),
			ProviderRunID:  req.ProviderRunID,
			Provider:       AdapterSlug,
			AdapterVersion: AdapterVersion,
			Capabilities:   capabilities,
			ResponseMetadata: map[string]any{
				adapter.RespMetaKeyEndpoint:          a.cfg.BaseURL,
				adapter.RespMetaKeyQueriedCoordinate: queryCoord,
				adapter.RespMetaKeyComponentCount:    len(reports),
			},
		},
		RawProviderResponse: rawEvidence,
	}, nil
}

// validateAndMapPURL verifies that rawPURL is a valid, exact-version PURL in a
// supported OSS Index ecosystem and returns both the canonical SCINTX PURL and
// the minimized coordinate sent to POST /api/v3/component-report (#95, #96, #97).
func validateAndMapPURL(rawPURL string) (canonicalPURL, queryCoord string, err error) {
	canonical, _, err := adapter.ValidateVersionedPURL(AdapterSlug, rawPURL, supportedPURLTypes)
	if err != nil {
		return "", "", err
	}
	return canonical, minimizeCoordinate(canonical), nil
}

// minimizeCoordinate adapts a canonical SCINTX PURL for OSS Index where the
// upstream /api/v3/component-report endpoint strays from the PURL spec (#96):
//  1. OSS Index fails to match coordinates containing ?qualifiers or #subpath.
//  2. OSS Index indexes Go/Composer versions without a leading 'v' prefix.
//  3. OSS Index matches '+' in build metadata literally rather than '%2B'.
func minimizeCoordinate(canonical string) string {
	coord := canonical
	if i := strings.IndexAny(coord, "?#"); i >= 0 {
		coord = coord[:i]
	}
	if at := strings.LastIndex(coord, "@"); at >= 0 {
		if at+2 < len(coord) && (coord[at+1] == 'v' || coord[at+1] == 'V') && coord[at+2] >= '0' && coord[at+2] <= '9' {
			coord = coord[:at+1] + coord[at+2:]
		}
		coord = coord[:at+1] + strings.ReplaceAll(coord[at+1:], "%2B", "+")
	}
	return coord
}
