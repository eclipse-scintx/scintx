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

// evaluateAdapters runs all registered provider adapters that support the
// submitted artifact's input type and attaches their normalized ProviderReport
// outputs to sub.Reports.
func (o *Orchestrator) evaluateAdapters(ctx context.Context, sub *api.Submission) error {
	artIn, inputType := o.prepareAdapterArtifact(sub)
	matched := 0
	reports := make([]json.RawMessage, 0, len(o.adapters))

	for _, prov := range o.adapters {
		desc := prov.Descriptor()
		if !slices.Contains(desc.SupportedInputs.Types, inputType) {
			continue
		}
		matched++

		reqCaps := make([]adapter.Capability, 0, len(desc.Capabilities))
		for capName := range desc.Capabilities {
			reqCaps = append(reqCaps, capName)
		}
		slices.Sort(reqCaps)

		res, err := prov.Evaluate(ctx, adapter.EvaluationRequest{
			SubmissionID:          sub.ID,
			ProviderRunID:         fmt.Sprintf("%s-%s-%d", sub.ID, desc.Slug, sub.Attempts),
			Artifact:              artIn,
			RequestedCapabilities: reqCaps,
		})
		if err != nil {
			var ae *adapter.AdapterError
			if errors.As(err, &ae) && ae.Retryable {
				return fmt.Errorf("%w: %w", ErrRetryable, err)
			}
			return err
		}
		if res != nil {
			raw, mErr := json.Marshal(res.Report)
			if mErr != nil {
				return mErr
			}
			reports = append(reports, json.RawMessage(raw))
		}
	}

	if matched == 0 {
		return fmt.Errorf("no configured provider adapter supports %s artifacts", inputType)
	}
	sub.Reports = reports
	return nil
}

// prepareAdapterArtifact attaches OpenContent when ContentMeta is present and
// returns the artifact alongside its canonical adapter.ArtifactInputType.
func (o *Orchestrator) prepareAdapterArtifact(sub *api.Submission) (adapter.ArtifactInput, adapter.ArtifactInputType) {
	art := sub.Artifact
	if art.ContentMeta != nil {
		if o.blobs != nil {
			id := sub.ID
			art.OpenContent = func() (io.ReadCloser, error) {
				return o.OpenContent(id)
			}
		}
		return art, adapter.InputTypeContent
	}
	if art.Digest != nil {
		return art, adapter.InputTypeDigest
	}
	return art, adapter.InputTypePURL
}
