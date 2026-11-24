// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package gateway_test

import (
	"context"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/extensions/providers/ossindex"
	"github.com/yeeth-security/scintx/extensions/providers/osv"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
	"github.com/yeeth-security/scintx/internal/policy"
)

type slowAdapter struct {
	delay time.Duration
}

func (s *slowAdapter) Descriptor() api.AdapterDescriptor {
	return api.AdapterDescriptor{
		Slug:                   "slow-scanner",
		AdapterVersion:         "1.0.0",
		SupportedSchemaVersion: api.SchemaVersionV1,
		SupportedInputs:        api.SupportedInputs{Types: []api.ArtifactInputType{api.InputTypePURL}},
		Capabilities:           []api.Capability{api.CapabilityVulnerabilities},
	}
}

func (s *slowAdapter) CheckAvailability(ctx context.Context) api.AvailabilityStatus {
	return api.AvailabilityStatus{State: api.StateReady, Available: true, CheckedAt: time.Now().UTC()}
}

func (s *slowAdapter) Evaluate(ctx context.Context, req api.EvaluationRequest) (*api.EvaluationResult, error) {
	select {
	case <-time.After(s.delay):
		return &api.EvaluationResult{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestOrchestrator_FullPipelineAndMissingCredentials(t *testing.T) {
	cfg := config.Default()
	store := gateway.NewStore()
	polMap, err := policy.LoadDir("../../policies")
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}

	osvAdapter := osv.NewAdapter(osv.Config{OfflineDemo: true}, nil)
	ossAdapter := ossindex.NewAdapter(ossindex.Config{Token: ""}, nil) // unconfigured -> missing_credentials

	orch := gateway.NewOrchestrator(cfg, store, polMap, []api.ProviderAdapter{osvAdapter, ossAdapter})

	// 1. Clean package -> satisfied verdict (#68).
	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"}, "baseline-security")
	if err != nil {
		t.Fatalf("unexpected submit error: %v", err)
	}
	orch.Wait()

	doneSub, ok := store.GetSubmission(sub.ID)
	if !ok || doneSub.Status != api.SubmissionCompleted {
		t.Fatalf("expected completed submission, got %+v", doneSub)
	}
	if doneSub.PolicyVerdict != api.VerdictSatisfied {
		t.Fatalf("got verdict %q, want satisfied", doneSub.PolicyVerdict)
	}

	agg, ok := store.GetAggregateReportBySubmission(sub.ID)
	if !ok {
		t.Fatal("expected aggregate report")
	}
	// Verify ossindex is recorded with available: false and reason "missing_credentials" (#68, #71, #73).
	foundOSS := false
	for _, p := range agg.Providers {
		if p.Slug == "ossindex" {
			foundOSS = true
			if p.Available || len(p.Reasons) == 0 || p.Reasons[0] != "missing_credentials" {
				t.Fatalf("expected ossindex missing_credentials, got %+v", p)
			}
		}
	}
	if !foundOSS {
		t.Fatal("ossindex not found in aggregateReport.providers")
	}

	// 2. Vulnerable package -> violated verdict (#68).
	vulnSub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"}, "")
	if err != nil {
		t.Fatal(err)
	}
	orch.Wait()
	doneVuln, _ := store.GetSubmission(vulnSub.ID)
	if doneVuln.PolicyVerdict != api.VerdictViolated {
		t.Fatalf("got verdict %q, want violated", doneVuln.PolicyVerdict)
	}
}

func TestOrchestrator_EvaluationDeadlineMarksRunIncomplete(t *testing.T) {
	cfg := config.Default()
	store := gateway.NewStore()
	pol, err := policy.ParseAndValidate([]byte(`schemaVersion: "1"
id: short-deadline
name: Short Deadline
version: 1.0.0
capabilities:
  - vulnerabilities
violations:
  provider-run-incomplete:
    description: A selected provider run did not complete successfully
    when: aggregateReport.providerRuns.any(r => r.status != "completed")
evaluationDeadline: 40ms
`))
	if err != nil {
		t.Fatal(err)
	}

	orch := gateway.NewOrchestrator(
		cfg,
		store,
		map[string]*api.PolicyDefinition{"short-deadline": pol},
		[]api.ProviderAdapter{&slowAdapter{delay: 500 * time.Millisecond}},
	)
	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.21"}, "short-deadline")
	if err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	agg, ok := store.GetAggregateReportBySubmission(sub.ID)
	if !ok || len(agg.ProviderRuns) != 1 {
		t.Fatalf("expected 1 provider run in aggregate report, got %+v", agg)
	}
	if agg.ProviderRuns[0].Status != api.RunStatusIncomplete {
		t.Fatalf("got run status %q, want incomplete", agg.ProviderRuns[0].Status)
	}
	polRep, ok := store.GetPolicyReportBySubmission(sub.ID)
	if !ok || polRep.PolicyVerdict != api.VerdictViolated {
		t.Fatalf("expected violated verdict from provider-run-incomplete, got %+v", polRep)
	}
}
