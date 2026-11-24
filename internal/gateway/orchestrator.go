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

// Orchestrator accepts validated artifact submissions and runs a lease-based
// background worker loop that claims and completes pending or lease-expired
// submissions from the persistent Store.
//
// Because work is claimed from the Store using time-bounded leases and an
// attempt limit, gateway restarts automatically pick up in-flight submissions
// and scans never get stuck—without needing a separate recovery service.
type Orchestrator struct {
	cfg           *config.Config
	store         Store
	leaseDuration time.Duration
	maxAttempts   int
	pollInterval  time.Duration

	wakeCh   chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewOrchestrator constructs a gateway orchestrator and starts its background
// lease-claiming worker loop, which immediately picks up any pending or
// lease-expired submissions already present in the Store.
func NewOrchestrator(cfg *config.Config, store Store) *Orchestrator {
	o := &Orchestrator{
		cfg:           cfg,
		store:         store,
		leaseDuration: DefaultLeaseDuration,
		maxAttempts:   DefaultMaxAttempts,
		pollInterval:  100 * time.Millisecond,
		wakeCh:        make(chan struct{}, 1),
		stopCh:        make(chan struct{}),
	}
	o.wg.Add(1)
	go o.workerLoop()
	o.signalWake()
	return o
}

// Submit validates an artifact, persists a Submission in "accepted" state,
// and signals the worker loop to claim and execute it.
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

	o.signalWake()
	return sub, nil
}

// DrainUntilIdle claims and executes all currently claimable submissions synchronously.
func (o *Orchestrator) DrainUntilIdle(ctx context.Context) {
	for {
		sub, ok, err := o.store.ClaimNextSubmission(ctx, time.Now().UTC(), o.leaseDuration, o.maxAttempts)
		if err != nil || !ok {
			return
		}
		o.ExecuteClaimedSubmission(ctx, sub)
	}
}

// Wait drains all currently claimable submissions until the queue is idle.
func (o *Orchestrator) Wait() {
	o.DrainUntilIdle(context.Background())
}

// Shutdown stops the background worker loop and waits for in-flight work to finish.
func (o *Orchestrator) Shutdown() {
	o.DrainUntilIdle(context.Background())
	o.stopOnce.Do(func() {
		close(o.stopCh)
	})
	o.wg.Wait()
}

func (o *Orchestrator) signalWake() {
	select {
	case o.wakeCh <- struct{}{}:
	default:
	}
}

func (o *Orchestrator) workerLoop() {
	defer o.wg.Done()
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	ctx := context.Background()
	for {
		o.DrainUntilIdle(ctx)
		select {
		case <-o.stopCh:
			return
		case <-o.wakeCh:
		case <-ticker.C:
		}
	}
}

// ExecuteClaimedSubmission finishes a submission that has already been claimed
// into "running" state. If an unrecoverable panic occurs, it fails closed.
func (o *Orchestrator) ExecuteClaimedSubmission(ctx context.Context, sub api.Submission) {
	defer func() {
		if r := recover(); r != nil {
			o.failSubmission(ctx, &sub, fmt.Sprintf("internal execution panic: %v", r))
		}
	}()

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
