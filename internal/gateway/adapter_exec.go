// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/eclipse-scintx/scintx/adapter"
	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// This file wires registered adapter.ProviderAdapter implementations into the
// gateway worker execution loop so claimed submissions are evaluated by
// compatible provider adapters and store their normalized ProviderReport list.

// NewOrchestratorWithAdapters constructs an Orchestrator that evaluates claimed
// submissions against the provided adapter.ProviderAdapter instances.
func NewOrchestratorWithAdapters(
	cfg *config.Config,
	store Store,
	blobs blob.Store,
	adapters ...adapter.ProviderAdapter,
) *Orchestrator {
	copied := make([]adapter.ProviderAdapter, 0, len(adapters))
	for _, a := range adapters {
		if a != nil {
			copied = append(copied, a)
		}
	}
	return newOrchestrator(cfg, store, withBlobs(blobs), func(o *Orchestrator) {
		o.adapters = copied
	})
}

// evaluateAdapters selects all registered provider adapters that support the
// submitted artifact's input type and ecosystem, runs them concurrently so
// multi-provider evaluations bound latency by the slowest provider rather than
// the sum of providers, and attaches their normalized ProviderReport outputs to
// sub.Reports in deterministic registration order.
func (o *Orchestrator) evaluateAdapters(ctx context.Context, sub *api.Submission) error {
	artIn, inputType := o.prepareAdapterArtifact(sub)
	matched := make([]adapter.ProviderAdapter, 0, len(o.adapters))

	for _, prov := range o.adapters {
		desc := prov.Descriptor()
		if !slices.Contains(desc.SupportedInputs.Types, inputType) {
			continue
		}
		if inputType == adapter.InputTypePURL && len(desc.SupportedInputs.Ecosystems) > 0 {
			if purlType, pErr := api.PurlType(artIn.PURL); pErr == nil && !slices.Contains(desc.SupportedInputs.Ecosystems, adapter.Ecosystem(purlType)) {
				continue
			}
		}
		matched = append(matched, prov)
	}

	if len(matched) == 0 {
		// Record provenance for every registered adapter explaining that none
		// supported the submitted artifact input or PURL ecosystem before failing closed (#97, #98).
		// what names the unsupported input. Both messages below are built from
		// it. The old code cut the second message out of the first by length,
		// which broke silently if the wording of the first one changed.
		what := fmt.Sprintf("%s artifacts", inputType)
		if inputType == adapter.InputTypePURL {
			if purlType, pErr := api.PurlType(artIn.PURL); pErr == nil && purlType != "" {
				what = fmt.Sprintf("PURL ecosystem %q", purlType)
			}
		}
		unmatchedErr := &adapter.AdapterError{Code: adapter.ErrUnsupportedInput, Message: "adapter does not support " + what}
		sub.Reports = make([]json.RawMessage, 0, len(o.adapters))
		for _, prov := range o.adapters {
			desc := prov.Descriptor()
			runID := fmt.Sprintf("%s-%s-%d", sub.ID, desc.Slug, sub.Attempts)
			if raw, mErr := json.Marshal(adapter.NewErroredProviderReport(desc, runID, unmatchedErr)); mErr == nil {
				sub.Reports = append(sub.Reports, json.RawMessage(raw))
			}
		}
		return fmt.Errorf("no configured provider adapter supports %s", what)
	}

	rawReports := make([]json.RawMessage, len(matched))
	errs := make([]error, len(matched))
	panics := make([]any, len(matched))
	var wg sync.WaitGroup
	wg.Add(len(matched))

	for i, prov := range matched {
		go func(idx int, p adapter.ProviderAdapter) {
			defer wg.Done()
			desc := p.Descriptor()
			runID := fmt.Sprintf("%s-%s-%d", sub.ID, desc.Slug, sub.Attempts)
			// Catch panics inside the child goroutine, record an errored
			// ProviderReport so provenance is preserved even on a panic, and
			// re-raise on the worker goroutine after wg.Wait().
			defer func() {
				if r := recover(); r != nil {
					panics[idx] = r
					if raw, mErr := json.Marshal(adapter.NewErroredProviderReport(desc, runID, nil)); mErr == nil {
						rawReports[idx] = json.RawMessage(raw)
					}
				}
			}()
			reqCaps := make([]adapter.Capability, 0, len(desc.Capabilities))
			for capName := range desc.Capabilities {
				reqCaps = append(reqCaps, capName)
			}
			slices.Sort(reqCaps)

			res, err := p.Evaluate(ctx, adapter.EvaluationRequest{
				SubmissionID: sub.ID, ProviderRunID: runID,
				Artifact: artIn, RequestedCapabilities: reqCaps,
			})
			if err != nil {
				if raw, mErr := json.Marshal(adapter.NewErroredProviderReport(desc, runID, err)); mErr == nil {
					rawReports[idx] = json.RawMessage(raw)
				}
				var ae *adapter.AdapterError
				if errors.As(err, &ae) && ae.Retryable {
					errs[idx] = fmt.Errorf("%w: %w", ErrRetryable, err)
					return
				}
				errs[idx] = err
				return
			}
			if res != nil {
				if raw, mErr := json.Marshal(res.Report); mErr == nil {
					rawReports[idx] = json.RawMessage(raw)
				} else {
					errs[idx] = mErr
				}
			}
		}(i, prov)
	}
	wg.Wait()

	// Always attach all completed and errored ProviderReports to sub.Reports
	// before re-panicking or returning an error so provenance is preserved on
	// every failure and retry path (#98).
	sub.Reports = slices.DeleteFunc(rawReports, func(r json.RawMessage) bool { return len(r) == 0 })
	for _, p := range panics {
		if p != nil {
			panic(p)
		}
	}
	return selectAdapterError(errs)
}

// selectAdapterError picks the highest-priority error across concurrent adapter
// runs: ErrStaleAttempt first (lease fencing), then any permanent non-retryable
// error (so a permanent failure in one provider never wastes retry attempts),
// and finally the first retryable error.
func selectAdapterError(errs []error) error {
	var firstRetryable, firstNonRetryable error
	for _, err := range errs {
		if err == nil {
			continue
		}
		if errors.Is(err, ErrStaleAttempt) {
			return err
		}
		if !errors.Is(err, ErrRetryable) && firstNonRetryable == nil {
			firstNonRetryable = err
		} else if firstRetryable == nil {
			firstRetryable = err
		}
	}
	if firstNonRetryable != nil {
		return firstNonRetryable
	}
	return firstRetryable
}

// prepareAdapterArtifact attaches OpenContent when ContentMeta is present and
// returns the artifact alongside its canonical adapter.ArtifactInputType.
func (o *Orchestrator) prepareAdapterArtifact(sub *api.Submission) (adapter.ArtifactInput, adapter.ArtifactInputType) {
	art := sub.Artifact
	if art.ContentMeta != nil {
		if o.blobs != nil {
			id := sub.ID
			art.OpenContent = func() (io.ReadCloser, error) { return o.OpenContent(id) }
		}
		return art, adapter.InputTypeContent
	}
	if art.Digest != nil {
		return art, adapter.InputTypeDigest
	}
	return art, adapter.InputTypePURL
}
