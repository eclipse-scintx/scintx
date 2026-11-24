// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/config"
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
	// retryBackoff is the wait before the first retry after ErrRetryable.
	// Later retries double it (see retryDelay in execution.go).
	retryBackoff time.Duration
	// execHook runs one claimed submission. It must return nil only when the
	// work really finished, and an error in every other case (including when
	// its context is canceled). A nil hook means no provider adapters are
	// wired in yet, so the submission completes without being scanned.
	execHook func(ctx context.Context, sub api.Submission) error
	// blobs holds the bytes of uploaded content until its submission is
	// finished (see content.go). Nil means content uploads are disabled.
	blobs blob.Store
	// These three settings drive the blob sweeper (see blob_sweep.go).
	sweepInterval  time.Duration
	orphanGrace    time.Duration
	staleUploadAge time.Duration

	workerCtx    context.Context
	cancelWorker context.CancelFunc
	wakeCh       chan struct{}
	idleNotify   chan struct{}
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	inFlight     atomic.Int32
	// lastClaimErrLog is when a claim error was last logged (Unix nanoseconds).
	// It limits the log to one line every few seconds during a storage outage.
	lastClaimErrLog atomic.Int64
}

// HasExecutor reports whether an execution hook is installed. The serve
// command uses it to warn that "completed" does not yet mean "scanned".
func (o *Orchestrator) HasExecutor() bool { return o.execHook != nil }

// orchestratorOption adjusts an Orchestrator before its workers start.
// Tests use it to shorten leases or install an execution hook.
type orchestratorOption func(*Orchestrator)

// NewOrchestrator constructs a gateway orchestrator and starts its concurrent
// background worker pool.
func NewOrchestrator(cfg *config.Config, store Store) *Orchestrator {
	return newOrchestrator(cfg, store)
}

// NewOrchestratorWithBlobs is NewOrchestrator plus a blob store, which turns
// on content uploads. It is a second constructor so the many callers that
// never upload content did not have to change. The serve command uses it.
func NewOrchestratorWithBlobs(cfg *config.Config, store Store, blobs blob.Store) *Orchestrator {
	return newOrchestrator(cfg, store, withBlobs(blobs))
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
		retryBackoff:         DefaultRetryBackoff,
		sweepInterval:        defaultSweepInterval,
		orphanGrace:          defaultOrphanGrace,
		staleUploadAge:       defaultStaleUploadAge,
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
	// The sweeper is counted in wg like a worker, so Shutdown waits for it.
	if o.blobs != nil {
		o.wg.Add(1)
		go o.sweepLoop()
	}
	o.signalWake()
	return o
}

// Submit and SubmitWithContent now live in submit.go. They moved there when
// blob storage was added, to keep this file small.

// DrainUntilIdle claims and executes all claimable submissions and waits for
// all concurrent in-flight worker executions to finish.
//
// DrainUntilIdle and Wait are helpers for tests and benchmarks. The server
// never calls them. They stay exported because tests in other packages
// (internal/server and test/e2e) need them. Note that a submission waiting
// out a retry backoff is not claimable yet, so these return before it runs.
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
