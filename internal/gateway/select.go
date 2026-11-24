// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package gateway

import (
	"context"
	"slices"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
)

// selectedAdapter pairs an eligible, selected ProviderAdapter with its pre-assigned ProviderRunID.
type selectedAdapter struct {
	adapter     api.ProviderAdapter
	runID       string
	matchedCaps []api.Capability
}

// selectProviders evaluates all registered adapters (and any unregistered policy slugs)
// through the four-stage matching pipeline defined in #68, #69, #71, and #73.
func selectProviders(
	ctx context.Context,
	cfg *config.Config,
	adapters []api.ProviderAdapter,
	pol *api.PolicyDefinition,
	artifact api.ArtifactInput,
) ([]api.ProviderSelection, []selectedAdapter) {
	registeredBySlug := make(map[string]api.ProviderAdapter, len(adapters))
	var selections []api.ProviderSelection
	var selected []selectedAdapter

	for _, adapter := range adapters {
		desc := adapter.Descriptor()
		registeredBySlug[desc.Slug] = adapter

		sel := evaluateSingleAdapter(ctx, cfg, adapter, desc, pol, artifact)
		if sel.Selected {
			runID := api.NewID("run")
			sel.ProviderRunID = runID
			selected = append(selected, selectedAdapter{
				adapter:     adapter,
				runID:       runID,
				matchedCaps: sel.MatchedCapabilities,
			})
		}
		selections = append(selections, sel)
	}

	// Record any providers explicitly referenced by the policy that are not registered (#68, #69, #71).
	seenUnregistered := make(map[string]bool)
	for _, slug := range append(append([]string{}, pol.Providers.Requested...), pol.Providers.Allowlist...) {
		if _, ok := registeredBySlug[slug]; ok || seenUnregistered[slug] {
			continue
		}
		seenUnregistered[slug] = true
		selections = append(selections, api.ProviderSelection{
			Slug:                slug,
			AdapterVersion:      "unknown",
			Available:           false,
			Eligible:            false,
			Selected:            false,
			MatchedCapabilities: []api.Capability{},
			Reasons:             []string{"provider_not_registered"},
		})
	}

	return selections, selected
}

func evaluateSingleAdapter(
	ctx context.Context,
	cfg *config.Config,
	adapter api.ProviderAdapter,
	desc api.AdapterDescriptor,
	pol *api.PolicyDefinition,
	artifact api.ArtifactInput,
) api.ProviderSelection {
	sel := api.ProviderSelection{
		Slug:                desc.Slug,
		AdapterVersion:      desc.AdapterVersion,
		MatchedCapabilities: []api.Capability{},
		Reasons:             []string{},
	}

	// Stage 1: Gateway configuration, schema version, and availability check (#69, #71, #73).
	if provCfg, ok := cfg.Providers[desc.Slug]; ok && !provCfg.Enabled {
		sel.Reasons = []string{"disabled_by_gateway"}
		return sel
	}
	if desc.SupportedSchemaVersion != api.SchemaVersionV1 {
		sel.Reasons = []string{"incompatible_adapter_schema"}
		return sel
	}
	avail := adapter.CheckAvailability(ctx)
	if !avail.Available {
		reasons := avail.Reasons
		if len(reasons) == 0 {
			reasons = []string{"upstream_unreachable"}
		}
		sel.Reasons = reasons
		return sel
	}
	sel.Available = true

	// Stage 2: Capability matching against the policy's top-level capabilities (#68, #71).
	for _, polCap := range pol.Capabilities {
		if slices.Contains(desc.Capabilities, polCap) {
			sel.MatchedCapabilities = append(sel.MatchedCapabilities, polCap)
		}
	}
	requestedExplicitly := slices.Contains(pol.Providers.Requested, desc.Slug)
	if len(sel.MatchedCapabilities) == 0 && !requestedExplicitly {
		sel.Reasons = []string{"capability_not_supported"}
		return sel
	}

	// Stage 3: Artifact input compatibility (#68, #71).
	if reason := checkInputCompatibility(desc.SupportedInputs, artifact); reason != "" {
		sel.Reasons = []string{reason}
		return sel
	}
	sel.Eligible = true

	// Stage 4: Policy allowlist and denylist filtering (#68, #71).
	if slices.Contains(pol.Providers.Denylist, desc.Slug) {
		sel.Reasons = []string{"excluded_by_policy_denylist"}
		return sel
	}
	if len(pol.Providers.Allowlist) > 0 && !slices.Contains(pol.Providers.Allowlist, desc.Slug) {
		sel.Reasons = []string{"excluded_by_policy_allowlist"}
		return sel
	}

	sel.Selected = true
	return sel
}

func checkInputCompatibility(sup api.SupportedInputs, art api.ArtifactInput) string {
	var failureReason string

	if slices.Contains(sup.Types, api.InputTypePURL) && art.PURL != "" {
		if len(sup.Ecosystems) == 0 {
			return ""
		}
		purlType, err := api.PurlType(art.PURL)
		if err == nil && slices.Contains(sup.Ecosystems, purlType) {
			return ""
		}
		failureReason = "unsupported_ecosystem"
	}

	if slices.Contains(sup.Types, api.InputTypeDigest) && art.Digest != nil {
		if len(sup.DigestAlgorithms) == 0 || slices.Contains(sup.DigestAlgorithms, art.Digest.Algorithm) {
			return ""
		}
		if failureReason == "" {
			failureReason = "unsupported_digest_algorithm"
		}
	}

	if slices.Contains(sup.Types, api.InputTypeContent) && len(art.Content) > 0 {
		if sup.MaxContentBytes <= 0 || int64(len(art.Content)) <= sup.MaxContentBytes {
			return ""
		}
		if failureReason == "" {
			failureReason = "artifact_size_exceeded"
		}
	}

	if failureReason != "" {
		return failureReason
	}
	return "unsupported_artifact_input"
}
