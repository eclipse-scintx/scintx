// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
)

// Orchestrator accepts validated artifact submissions and manages their
// lifecycle state in memory.
type Orchestrator struct {
	cfg   *config.Config
	store *Store
	wg    sync.WaitGroup
}

// NewOrchestrator constructs a gateway orchestrator.
func NewOrchestrator(cfg *config.Config, store *Store) *Orchestrator {
	return &Orchestrator{
		cfg:   cfg,
		store: store,
	}
}

// Submit validates an artifact, persists a Submission in "accepted" state,
// and transitions it through "running" to "completed" asynchronously.
func (o *Orchestrator) Submit(ctx context.Context, artifact api.ArtifactInput) (api.Submission, error) {
	normArtifact, err := api.ValidateAndNormalizeArtifact(artifact, o.cfg.Gateway.MaxContentBytes)
	if err != nil {
		return api.Submission{}, err
	}

	now := time.Now().UTC()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      normArtifact,
	}
	o.store.PutSubmission(sub)

	o.wg.Add(1)
	go func(s api.Submission) {
		defer o.wg.Done()
		o.ExecuteSubmission(context.WithoutCancel(ctx), s)
	}(sub)

	return sub, nil
}

// Wait blocks until all in-flight submissions complete.
func (o *Orchestrator) Wait() {
	o.wg.Wait()
}

// ExecuteSubmission runs the submission lifecycle synchronously.
func (o *Orchestrator) ExecuteSubmission(_ context.Context, sub api.Submission) {
	sub.Status = api.SubmissionRunning
	o.store.PutSubmission(sub)

	doneAt := time.Now().UTC()
	sub.Status = api.SubmissionCompleted
	sub.CompletedAt = &doneAt
	o.store.PutSubmission(sub)
}
