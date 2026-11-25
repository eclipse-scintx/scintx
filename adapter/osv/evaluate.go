// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
	"github.com/eclipse-scintx/scintx/api"
)

// This file implements Evaluate, stub-record hydration via GET /v1/vulns/{id},
// and PURL input validation for the OSV adapter (#94, #96).

const (
	// malwareIDPrefix identifies OSV malicious-package advisories (MAL-*).
	malwareIDPrefix = "MAL-"

	// vscodeExtensionPURLPrefix is the canonical PURL prefix for VS Code / Open VSX extensions.
	vscodeExtensionPURLPrefix = "pkg:" + string(adapter.EcosystemVSCodeExtension) + "/"
)

// Evaluate queries OSV for the submitted PURL, retrieves full vulnerability
// records via GET /v1/vulns/{id} whenever query entries are stubs (#94), and
// returns a normalized ProviderReport for the requested capabilities.
func (a *Adapter) Evaluate(ctx context.Context, req adapter.EvaluationRequest) (*adapter.EvaluationResult, error) {
	canonicalPURL, err := validateSupportedPURL(req.Artifact.PURL)
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

	// 1. Query POST /v1/query by canonical PURL across all pages.
	vulns, rawPages, err := a.queryAllPages(ctx, QueryRequest{
		Package: &PackageQuery{PURL: canonicalPURL},
	})
	if err != nil {
		return nil, err
	}

	// 2. Fall back to the Open VSX ecosystem query when a pkg:vscode-extension PURL
	// returned zero direct matches (#96).
	if len(vulns) == 0 && strings.HasPrefix(canonicalPURL, vscodeExtensionPURLPrefix) {
		if extName, version, ok := parseVSCodeExtensionPURL(canonicalPURL); ok {
			fallbackVulns, fallbackPages, err := a.queryAllPages(ctx, QueryRequest{
				Package: &PackageQuery{
					Ecosystem: openVSXEcosystem,
					Name:      extName,
				},
				Version: version,
			})
			if err != nil {
				return nil, err
			}
			vulns = fallbackVulns
			rawPages = append(rawPages, fallbackPages...)
		}
	}

	// 3. Retrieve full records via GET /v1/vulns/{id} for any stub entries (#94).
	hydratedVulns, hydratedRaw, err := a.hydrateRecords(ctx, vulns)
	if err != nil {
		return nil, err
	}

	// 4. Normalize records into the requested SCINTX capabilities and checks.
	vulnFindings := make([]adapter.Finding, 0)
	threatFindings := make([]adapter.Finding, 0)
	for _, v := range hydratedVulns {
		isMalware := strings.HasPrefix(v.ID, malwareIDPrefix)
		if isMalware {
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

// hydrateRecords ensures every Vulnerability returned by a query contains the
// full fields needed for normalization. When a query entry is a stub (only id
// and modified), hydrateRecords fetches the full record via GET /v1/vulns/{id}.
func (a *Adapter) hydrateRecords(
	ctx context.Context,
	vulns []Vulnerability,
) ([]Vulnerability, []json.RawMessage, error) {
	hydrated := make([]Vulnerability, 0, len(vulns))
	var fetchedRaw []json.RawMessage

	for _, v := range vulns {
		if strings.TrimSpace(v.ID) == "" {
			return nil, nil, &adapter.AdapterError{
				Code:      adapter.ErrMalformedResponse,
				Message:   "OSV advisory record is missing required id field",
				Retryable: false,
			}
		}
		if isStubRecord(v) {
			full, raw, err := a.GetVulnerability(ctx, v.ID)
			if err != nil {
				return nil, nil, err
			}
			hydrated = append(hydrated, full)
			fetchedRaw = append(fetchedRaw, raw)
			continue
		}
		hydrated = append(hydrated, v)
	}
	return hydrated, fetchedRaw, nil
}

// validateSupportedPURL verifies that the input PURL is present, canonical,
// includes a package version, and belongs to a supported OSV ecosystem.
func validateSupportedPURL(rawPURL string) (string, error) {
	trimmed := strings.TrimSpace(rawPURL)
	if trimmed == "" {
		return "", &adapter.AdapterError{
			Code:      adapter.ErrUnsupportedInput,
			Message:   "osv adapter requires a package PURL",
			Retryable: false,
		}
	}
	canonical, err := api.CanonicalPurl(trimmed)
	if err != nil {
		return "", &adapter.AdapterError{
			Code:      adapter.ErrUnsupportedInput,
			Message:   fmt.Sprintf("invalid package PURL: %v", err),
			Retryable: false,
			Cause:     err,
		}
	}
	purlType, err := api.PurlType(canonical)
	if err != nil || !slices.Contains(supportedPURLTypes, adapter.Ecosystem(purlType)) {
		return "", &adapter.AdapterError{
			Code:      adapter.ErrUnsupportedInput,
			Message:   fmt.Sprintf("osv adapter does not support PURL ecosystem %q", purlType),
			Retryable: false,
		}
	}
	if _, hasVersion, err := api.PurlVersion(canonical); err != nil || !hasVersion {
		return "", &adapter.AdapterError{
			Code:      adapter.ErrUnsupportedInput,
			Message:   "osv adapter requires a versioned package PURL",
			Retryable: false,
		}
	}
	return canonical, nil
}
