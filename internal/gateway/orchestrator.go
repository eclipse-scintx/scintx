// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
)

// Orchestrator accepts validated artifact submissions and runs a lease-based
// background worker loop that claims, heartbeats, and completes pending or
// lease-expired submissions from the persistent Store.
type Orchestrator struct {
	cfg           *config.Config
	store         Store
	leaseDuration time.Duration
	maxAttempts   int
	pollInterval  time.Duration
	execHook      func(ctx context.Context, sub api.Submission) error

	wakeCh   chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	drainMu  sync.Mutex
}

// NewOrchestrator constructs a gateway orchestrator and starts its background
// lease-claiming worker loop.
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
	o.drainMu.Lock()
	defer o.drainMu.Unlock()
	for {
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

// ExecuteClaimedSubmission runs a claimed submission while periodically
// renewing its lease every leaseDuration/3. If another worker re-claims the
// submission (fencing token mismatch), execCtx is canceled and the stale
// worker aborts without overwriting the newer attempt.
func (o *Orchestrator) ExecuteClaimedSubmission(ctx context.Context, sub api.Submission) {
	execCtx, cancelExec := context.WithCancel(ctx)
	stopHeartbeat := o.startLeaseHeartbeat(execCtx, cancelExec, sub)
	defer stopHeartbeat()

	defer func() {
		if r := recover(); r != nil {
			o.failSubmission(ctx, &sub, fmt.Sprintf("internal execution panic: %v", r))
		}
	}()

	if o.execHook != nil {
		if err := o.execHook(execCtx, sub); err != nil {
			if errors.Is(err, ErrStaleAttempt) || execCtx.Err() != nil {
				return
			}
			o.failSubmission(ctx, &sub, err.Error())
			return
		}
	}
	if execCtx.Err() != nil {
		return
	}

	if err := sub.TransitionTo(api.SubmissionCompleted, "", time.Now().UTC()); err != nil {
		o.failSubmission(ctx, &sub, err.Error())
		return
	}
	if err := o.store.PutSubmission(ctx, sub); err != nil && !errors.Is(err, ErrStaleAttempt) {
		o.failSubmission(ctx, &sub, fmt.Sprintf("persist completed state: %v", err))
	}
}

func (o *Orchestrator) startLeaseHeartbeat(execCtx context.Context, cancelExec context.CancelFunc, sub api.Submission) func() {
	interval := o.leaseDuration / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-execCtx.Done():
				return
			case <-ticker.C:
				err := o.store.RenewLease(execCtx, sub.ID, sub.Attempts, time.Now().UTC(), o.leaseDuration)
				if errors.Is(err, ErrStaleAttempt) {
					cancelExec()
					return
				}
			}
		}
	}()
	return func() {
		close(done)
		cancelExec()
		wg.Wait()
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
