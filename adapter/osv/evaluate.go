// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file implements Evaluate and stub-record hydration via GET /v1/vulns/{id}
// for the OSV adapter (#94, #96).

// malwareIDPrefix identifies OSV malicious-package advisories (MAL-*).
const malwareIDPrefix = "MAL-"

// Evaluate queries OSV for the submitted PURL, retrieves full vulnerability
// records via GET /v1/vulns/{id} whenever query entries are stubs (#94), and
// returns a normalized ProviderReport for the requested capabilities.
func (a *Adapter) Evaluate(ctx context.Context, req adapter.EvaluationRequest) (*adapter.EvaluationResult, error) {
	canonicalPURL, _, err := adapter.ValidateVersionedPURL(AdapterSlug, req.Artifact.PURL, supportedPURLTypes)
	if err != nil {
		return nil, err
	}

	var wantVulns, wantThreats bool
	for _, c := range req.RequestedCapabilities {
		switch c {
		case adapter.CapabilityVulnerabilities:
			wantVulns = true
		case adapter.CapabilityThreats:
			wantThreats = true
		}
	}
	if !wantVulns && !wantThreats {
		return nil, &adapter.AdapterError{
			Code:      adapter.ErrUnsupportedInput,
			Message:   "osv adapter does not support any of the requested capabilities",
			Retryable: false,
		}
	}

	queryPURL := mapOSVQueryPURL(canonicalPURL)
	// Reject PURLs that OSV would answer with a false "no findings" (#96).
	if err = validateOSVQueryPURL(queryPURL); err != nil {
		return nil, err
	}
	vulns, rawPages, err := a.queryAllPages(ctx, QueryRequest{
		Package: &PackageQuery{PURL: queryPURL},
	})
	if err != nil {
		return nil, err
	}

	// Fall back to ecosystem+name+version queries when OSV's PURL indexing
	// strays from the PURL spec (VS Code / Open VSX extensions, mixed-case Go
	// module paths, and Alpine APK PURLs with a ?distro= qualifier) (#96).
	if len(vulns) == 0 {
		for _, fbReq := range buildFallbackQueries(queryPURL) {
			fbVulns, fbPages, fbErr := a.queryAllPages(ctx, fbReq)
			if fbErr != nil {
				return nil, fbErr
			}
			rawPages = append(rawPages, fbPages...)
			if len(fbVulns) > 0 {
				vulns = fbVulns
				break
			}
		}
	}

	hydratedVulns, hydratedRaw, err := a.hydrateRecords(ctx, vulns)
	if err != nil {
		return nil, err
	}

	vulnFindings := make([]adapter.Finding, 0)
	threatFindings := make([]adapter.Finding, 0)
	for _, v := range hydratedVulns {
		if strings.HasPrefix(v.ID, malwareIDPrefix) {
			if wantThreats {
				threatFindings = append(threatFindings, normalizeFinding(v, canonicalPURL, true))
			}
			continue
		}
		if wantVulns {
			vulnFindings = append(vulnFindings, normalizeFinding(v, canonicalPURL, false))
		}
	}

	capabilities := make(map[adapter.Capability]adapter.CapabilityReport)
	if wantVulns {
		capabilities[adapter.CapabilityVulnerabilities] = adapter.NewCompletedCapabilityReport(adapter.CheckKnownVulnerabilities, vulnFindings)
	}
	if wantThreats {
		capabilities[adapter.CapabilityThreats] = adapter.NewCompletedCapabilityReport(adapter.CheckMalware, threatFindings)
	}

	evidenceMap := map[string]any{adapter.EvidenceKeyPages: rawPages, adapter.EvidenceKeyCount: len(hydratedVulns)}
	if len(hydratedRaw) > 0 {
		evidenceMap[adapter.EvidenceKeyHydratedRecords] = hydratedRaw
	}
	rawEvidence, _ := json.Marshal(evidenceMap)

	return &adapter.EvaluationResult{
		Report: adapter.ProviderReport{
			SchemaVersion: adapter.SchemaVersionV1, ProviderRunID: req.ProviderRunID,
			Provider: AdapterSlug, AdapterVersion: AdapterVersion, Capabilities: capabilities,
		},
		RawProviderResponse: rawEvidence,
	}, nil
}

func hydrateRecordStub(ctx context.Context, a *Adapter, v Vulnerability) (Vulnerability, json.RawMessage, error) {
	if isStubRecord(v) {
		return a.GetVulnerability(ctx, v.ID)
	}
	return v, nil, nil
}

func (a *Adapter) hydrateRecords(ctx context.Context, vulns []Vulnerability) ([]Vulnerability, []json.RawMessage, error) {
	hydrated := make([]Vulnerability, 0, len(vulns))
	var fetchedRaw []json.RawMessage
	for _, v := range vulns {
		if strings.TrimSpace(v.ID) == "" {
			return nil, nil, &adapter.AdapterError{Code: adapter.ErrMalformedResponse, Message: "OSV advisory record is missing required id field"}
		}
		full, raw, err := hydrateRecordStub(ctx, a, v)
		if err != nil {
			return nil, nil, err
		}
		hydrated = append(hydrated, full)
		if raw != nil {
			fetchedRaw = append(fetchedRaw, raw)
		}
	}
	return hydrated, fetchedRaw, nil
}
