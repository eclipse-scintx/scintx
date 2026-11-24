// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/policy"
)

// Orchestrator manages submission creation, provider execution, aggregation, and policy evaluation.
type Orchestrator struct {
	cfg      *config.Config
	store    *Store
	policies map[string]*api.PolicyDefinition
	adapters []api.ProviderAdapter
	wg       sync.WaitGroup
}

// NewOrchestrator constructs a gateway Orchestrator with loaded configuration, policies, and adapters.
func NewOrchestrator(
	cfg *config.Config,
	store *Store,
	policies map[string]*api.PolicyDefinition,
	adapters []api.ProviderAdapter,
) *Orchestrator {
	return &Orchestrator{
		cfg:      cfg,
		store:    store,
		policies: policies,
		adapters: adapters,
	}
}

// ResolvePolicy returns the requested policy or the gateway's default policy when policyID is empty (#65, #68).
func (o *Orchestrator) ResolvePolicy(policyID string) (*api.PolicyDefinition, error) {
	if policyID == "" {
		policyID = o.cfg.Gateway.DefaultPolicy
	}
	pol, ok := o.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("unknown policy %q", policyID)
	}
	return pol, nil
}

// Policies returns all loaded policy definitions.
func (o *Orchestrator) Policies() map[string]*api.PolicyDefinition {
	return o.policies
}

// Adapters returns all registered provider adapters.
func (o *Orchestrator) Adapters() []api.ProviderAdapter {
	return o.adapters
}

// Submit validates the artifact and policy reference, stores an accepted Submission,
// and starts asynchronous orchestration (#65, #67, #68).
func (o *Orchestrator) Submit(ctx context.Context, artifact api.ArtifactInput, policyID string) (*api.Submission, error) {
	if err := api.ValidateAndNormalizeArtifact(&artifact, o.cfg.Gateway.MaxArtifactBytes); err != nil {
		return nil, err
	}
	pol, err := o.ResolvePolicy(policyID)
	if err != nil {
		return nil, err
	}

	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    time.Now().UTC(),
		Artifact:      artifact,
		Policy: api.PolicyReportRef{
			ID:      pol.ID,
			Version: pol.Version,
		},
	}
	o.store.PutSubmission(sub)

	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		o.ExecuteSubmission(ctx, sub.ID, pol)
	}()

	return &sub, nil
}

// Wait blocks until all in-flight asynchronous submissions complete.
func (o *Orchestrator) Wait() {
	o.wg.Wait()
}

// ExecuteSubmission runs the 3-step SCINTX pipeline for an accepted submission (#65, #68, #72, #75).
func (o *Orchestrator) ExecuteSubmission(parentCtx context.Context, submissionID string, pol *api.PolicyDefinition) {
	sub, ok := o.store.GetSubmission(submissionID)
	if !ok {
		return
	}
	sub.Status = api.SubmissionRunning
	o.store.PutSubmission(sub)

	deadline := pol.ParsedDeadline
	if deadline <= 0 {
		deadline = 30 * time.Second
	}
	evalCtx, cancel := context.WithTimeout(parentCtx, deadline)
	defer cancel()

	// Step 1: Select compatible providers and record selection reasons (#68, #71).
	selections, selected := selectProviders(evalCtx, o.cfg, o.adapters, pol, sub.Artifact)

	// Step 2: Execute selected providers concurrently up to the evaluationDeadline (#68, #74, #75).
	runs, reports := o.runSelectedProviders(evalCtx, sub, selected)

	// Snapshot the immutable Aggregate Report (#68).
	agg := api.AggregateReport{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("aggregate"),
		Submission: api.SubmissionRef{
			ID:         sub.ID,
			AcceptedAt: sub.AcceptedAt,
		},
		Artifact: sub.Artifact,
		Gateway: api.GatewayInfo{
			InstanceID: o.cfg.Gateway.InstanceID,
			Version:    o.cfg.Gateway.Version,
			Configuration: api.GatewayConfigRef{
				Revision:    o.cfg.Revision,
				SnapshotRef: o.cfg.SnapshotRef,
			},
		},
		Policy: api.PolicySummary{
			ID:                   pol.ID,
			Version:              pol.Version,
			Capabilities:         pol.Capabilities,
			EvaluationDeadlineMs: deadline.Milliseconds(),
		},
		Providers:       selections,
		ProviderRuns:    runs,
		ProviderReports: reports,
	}
	o.store.PutAggregateReport(agg)

	// Step 3: Evaluate the Aggregate Report against the selected policy (#68, #75).
	polReport, err := policy.Evaluate(pol, &agg)
	if err != nil {
		sub.Status = api.SubmissionFailed
		sub.Error = err.Error()
		o.store.PutSubmission(sub)
		return
	}
	o.store.PutPolicyReport(*polReport)

	now := time.Now().UTC()
	summary := summarizeRuns(runs)
	sub.Status = api.SubmissionCompleted
	sub.CompletedAt = &now
	sub.ProviderSummary = &summary
	sub.EvidenceStatus = polReport.EvidenceStatus
	sub.PolicyVerdict = polReport.PolicyVerdict
	sub.AggregateReportID = agg.ID
	sub.PolicyReportID = polReport.ID
	o.store.PutSubmission(sub)
}
