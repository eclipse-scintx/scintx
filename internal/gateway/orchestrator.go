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
)

// Orchestrator accepts validated artifact submissions and manages their
// lifecycle state machine in the configured persistent Store.
type Orchestrator struct {
	cfg   *config.Config
	store Store
	wg    sync.WaitGroup
}

// NewOrchestrator constructs a gateway orchestrator.
func NewOrchestrator(cfg *config.Config, store Store) *Orchestrator {
	return &Orchestrator{
		cfg:   cfg,
		store: store,
	}
}

// Submit validates an artifact, persists a Submission in "accepted" state,
// and transitions it through "running" to a terminal state ("completed" or
// "failed") asynchronously.
func (o *Orchestrator) Submit(ctx context.Context, artifact api.ArtifactInput) (api.Submission, error) {
	normArtifact, err := api.ValidateAndNormalizeArtifact(artifact, o.cfg.Gateway.MaxContentBytes)
	if err != nil {
		return api.Submission{}, err
	}

	now := time.Now().UTC()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		AcceptedAt:    now,
		Artifact:      normArtifact,
	}
	if err := sub.TransitionTo(api.SubmissionAccepted, "", now); err != nil {
		return api.Submission{}, err
	}
	if err := o.store.PutSubmission(ctx, sub); err != nil {
		return api.Submission{}, err
	}

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

// ExecuteSubmission drives the submission state machine from "accepted" to
// "running" and then to "completed". If any step fails or panics, it fails
// closed by transitioning the submission to "failed".
func (o *Orchestrator) ExecuteSubmission(ctx context.Context, sub api.Submission) {
	defer func() {
		if r := recover(); r != nil {
			o.failSubmission(ctx, &sub, fmt.Sprintf("internal execution panic: %v", r))
		}
	}()

	if err := sub.TransitionTo(api.SubmissionRunning, "", time.Now().UTC()); err != nil {
		o.failSubmission(ctx, &sub, err.Error())
		return
	}
	if err := o.store.PutSubmission(ctx, sub); err != nil {
		o.failSubmission(ctx, &sub, fmt.Sprintf("persist running state: %v", err))
		return
	}

	if err := sub.TransitionTo(api.SubmissionCompleted, "", time.Now().UTC()); err != nil {
		o.failSubmission(ctx, &sub, err.Error())
		return
	}
	if err := o.store.PutSubmission(ctx, sub); err != nil {
		o.failSubmission(ctx, &sub, fmt.Sprintf("persist completed state: %v", err))
	}
}

func (o *Orchestrator) failSubmission(ctx context.Context, sub *api.Submission, reason string) {
	if sub.Status.IsTerminal() {
		return
	}
	if err := sub.TransitionTo(api.SubmissionFailed, reason, time.Now().UTC()); err == nil {
		_ = o.store.PutSubmission(ctx, *sub)
	}
}
