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

// Orchestrator accepts validated artifact submissions and runs a lease-based
// background worker loop that claims, heartbeats, and completes pending or
// lease-expired submissions from the persistent Store.
type Orchestrator struct {
	cfg                  *config.Config
	store                Store
	leaseDuration        time.Duration
	maxAttempts          int
	maxExecutionDuration time.Duration
	pollInterval         time.Duration
	execHook             func(ctx context.Context, sub api.Submission) error

	workerCtx    context.Context
	cancelWorker context.CancelFunc
	wakeCh       chan struct{}
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	drainMu      sync.Mutex
}

// NewOrchestrator constructs a gateway orchestrator and starts its background
// lease-claiming worker loop.
func NewOrchestrator(cfg *config.Config, store Store) *Orchestrator {
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	o := &Orchestrator{
		cfg:                  cfg,
		store:                store,
		leaseDuration:        DefaultLeaseDuration,
		maxAttempts:          DefaultMaxAttempts,
		maxExecutionDuration: DefaultMaxExecutionDuration,
		pollInterval:         100 * time.Millisecond,
		workerCtx:            workerCtx,
		cancelWorker:         cancelWorker,
		wakeCh:               make(chan struct{}, 1),
		stopCh:               make(chan struct{}),
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
	o.drainLoop(ctx, false)
}

func (o *Orchestrator) drainLoop(ctx context.Context, stopOnShutdown bool) {
	o.drainMu.Lock()
	defer o.drainMu.Unlock()
	for {
		if stopOnShutdown {
			select {
			case <-o.stopCh:
				return
			default:
			}
		}
		if ctx.Err() != nil {
			return
		}
		sub, ok, err := o.store.ClaimNextSubmission(ctx, time.Now().UTC(), o.leaseDuration, o.maxAttempts)
		if err != nil || !ok {
			return
		}
		o.ExecuteClaimedSubmission(ctx, sub)
	}
}

// Wait drains all claimable submissions and waits for any in-flight worker
// executions to complete.
func (o *Orchestrator) Wait() {
	o.DrainUntilIdle(context.Background())
}

// Shutdown stops claiming new submissions and waits for any currently active
// execution to finish.
func (o *Orchestrator) Shutdown() {
	o.ShutdownWithContext(context.Background())
}

// ShutdownWithContext closes stopCh first so no new submissions are claimed,
// then waits for any in-flight submission to finish up to the ctx deadline.
// If ctx expires first, the active worker is canceled and releases its lease.
func (o *Orchestrator) ShutdownWithContext(ctx context.Context) {
	o.stopOnce.Do(func() {
		close(o.stopCh)
	})
	done := make(chan struct{})
	go func() {
		o.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		o.cancelWorker()
	case <-ctx.Done():
		o.cancelWorker()
		<-done
	}
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

	for {
		o.drainLoop(o.workerCtx, true)
		select {
		case <-o.stopCh:
			return
		case <-o.workerCtx.Done():
			return
		case <-o.wakeCh:
		case <-ticker.C:
		}
	}
}
