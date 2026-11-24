// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
)

// Orchestrator accepts validated artifact submissions and runs a concurrent
// pool of lease-based worker goroutines. Running multiple workers in parallel
// prevents multi-minute local binary analyses from head-of-line blocking fast
// remote HTTP adapter lookups.
type Orchestrator struct {
	cfg                  *config.Config
	store                Store
	workers              int
	leaseDuration        time.Duration
	maxAttempts          int
	maxExecutionDuration time.Duration
	pollInterval         time.Duration
	execHook             func(ctx context.Context, sub api.Submission) error

	workerCtx    context.Context
	cancelWorker context.CancelFunc
	wakeCh       chan struct{}
	idleNotify   chan struct{}
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	inFlight     atomic.Int32
}

// orchestratorOption adjusts an Orchestrator before its workers start.
// Tests use it to shorten leases or install an execution hook.
type orchestratorOption func(*Orchestrator)

// NewOrchestrator constructs a gateway orchestrator and starts its concurrent
// background worker pool.
func NewOrchestrator(cfg *config.Config, store Store) *Orchestrator {
	return newOrchestrator(cfg, store)
}

// newOrchestrator builds the orchestrator, applies opts, and only then starts
// the workers. Settings must never change after the workers start: the
// workers read them without a lock, so a later write is a data race. (Tests
// used to set fields after construction, which the race detector caught.)
func newOrchestrator(cfg *config.Config, store Store, opts ...orchestratorOption) *Orchestrator {
	if cfg == nil {
		cfg = config.Default()
	}
	workers := cfg.Gateway.Workers
	if workers <= 0 {
		workers = config.DefaultWorkers()
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	o := &Orchestrator{
		cfg:                  cfg,
		store:                store,
		workers:              workers,
		leaseDuration:        DefaultLeaseDuration,
		maxAttempts:          DefaultMaxAttempts,
		maxExecutionDuration: DefaultMaxExecutionDuration,
		pollInterval:         100 * time.Millisecond,
		workerCtx:            workerCtx,
		cancelWorker:         cancelWorker,
		wakeCh:               make(chan struct{}, workers),
		idleNotify:           make(chan struct{}, 1),
		stopCh:               make(chan struct{}),
	}
	// Apply options BEFORE starting any goroutine that reads these fields.
	for _, opt := range opts {
		opt(o)
	}
	for i := 0; i < workers; i++ {
		o.wg.Add(1)
		go o.workerLoop()
	}
	o.signalWake()
	return o
}

// Submit validates an artifact, persists a Submission in "accepted" state,
// and wakes an idle worker to claim and execute it immediately.
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

// DrainUntilIdle claims and executes all claimable submissions and waits for
// all concurrent in-flight worker executions to finish.
func (o *Orchestrator) DrainUntilIdle(ctx context.Context) {
	for {
		if o.claimAndExecuteOne(ctx, false) {
			continue
		}
		if o.inFlight.Load() == 0 {
			if !o.claimAndExecuteOne(ctx, false) && o.inFlight.Load() == 0 {
				return
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-o.idleNotify:
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// Wait drains all claimable submissions and waits for all concurrent workers to finish.
func (o *Orchestrator) Wait() { o.DrainUntilIdle(context.Background()) }

// Shutdown stops claiming new submissions and waits for active executions to finish.
func (o *Orchestrator) Shutdown() { o.ShutdownWithContext(context.Background()) }

// ShutdownWithContext closes stopCh first so no new submissions are claimed,
// then waits for any in-flight workers up to the ctx deadline.
func (o *Orchestrator) ShutdownWithContext(ctx context.Context) {
	o.stopOnce.Do(func() { close(o.stopCh) })
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
