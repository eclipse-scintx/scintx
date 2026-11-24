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

// NewOrchestrator constructs a gateway orchestrator and starts its concurrent
// background worker pool.
func NewOrchestrator(cfg *config.Config, store Store) *Orchestrator {
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

// claimAndExecuteOne atomically claims a single eligible submission and executes
// it outside any global lock so other workers can run in parallel.
func (o *Orchestrator) claimAndExecuteOne(ctx context.Context, stopOnShutdown bool) bool {
	if stopOnShutdown {
		select {
		case <-o.stopCh:
			return false
		default:
		}
	}
	if ctx.Err() != nil {
		return false
	}
	o.inFlight.Add(1)
	defer func() {
		if o.inFlight.Add(-1) == 0 {
			select {
			case o.idleNotify <- struct{}{}:
			default:
			}
		}
	}()
	sub, ok, err := o.store.ClaimNextSubmission(ctx, time.Now().UTC(), o.leaseDuration, o.maxAttempts)
	if err != nil || !ok {
		return false
	}
	// Cascade wake signal so another idle worker immediately claims the next
	// queued submission while this worker executes sub.
	o.signalWake()
	o.ExecuteClaimedSubmission(ctx, sub)
	return true
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
		for o.claimAndExecuteOne(o.workerCtx, true) {
		}
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
