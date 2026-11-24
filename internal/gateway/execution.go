// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// ExecuteClaimedSubmission runs a claimed submission under a bounded per-attempt
// timeout while periodically renewing its lease every leaseDuration/3.
//
// Four cancellation and error cases are handled explicitly:
//  1. Lease lost or fenced (ErrStaleAttempt or local leaseDeadline expired):
//     abort immediately without touching storage.
//  2. Parent context canceled (graceful shutdown timeout):
//     release the active lease immediately so the next gateway instance can
//     claim the submission with zero wait delay.
//  3. Per-attempt execution timeout exceeded (maxExecutionDuration):
//     fail closed by transitioning the submission to "failed".
//  4. Transient retryable error (ErrRetryable) with remaining attempts:
//     release the active lease and wake a worker to retry up to maxAttempts.
func (o *Orchestrator) ExecuteClaimedSubmission(ctx context.Context, sub api.Submission) {
	maxDur := o.maxExecutionDuration
	if maxDur <= 0 {
		maxDur = DefaultMaxExecutionDuration
	}

	execCtx, cancelExec := context.WithTimeout(ctx, maxDur)
	var leaseLost atomic.Bool
	stopHeartbeat := o.startLeaseHeartbeat(execCtx, cancelExec, sub, &leaseLost)
	defer stopHeartbeat()

	defer func() {
		if r := recover(); r != nil && !leaseLost.Load() {
			o.failSubmission(context.Background(), &sub, fmt.Sprintf("internal execution panic: %v", r))
		}
	}()

	var hookErr error
	if o.execHook != nil {
		hookErr = o.execHook(execCtx, sub)
	}

	if leaseLost.Load() || errors.Is(hookErr, ErrStaleAttempt) {
		return
	}
	if ctx.Err() != nil {
		// Parent shutdown context expired; release the lease for instant handoff.
		_ = o.store.ReleaseLease(context.Background(), sub.ID, sub.Attempts)
		return
	}
	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		o.failSubmission(context.Background(), &sub, fmt.Sprintf("submission execution timed out after %s", maxDur))
		return
	}
	if hookErr != nil {
		// If the adapter returned a transient retryable error and we have not
		// exhausted maxAttempts, release the lease so the job retries cleanly.
		if errors.Is(hookErr, ErrRetryable) && sub.Attempts < o.maxAttempts {
			if err := o.store.ReleaseLease(context.Background(), sub.ID, sub.Attempts); err == nil {
				o.signalWake()
				return
			}
		}
		o.failSubmission(ctx, &sub, hookErr.Error())
		return
	}

	// Transition a copy to completed first so sub.Status remains "running"
	// in memory if persisting the completed state fails.
	completedSub := sub
	if err := completedSub.TransitionTo(api.SubmissionCompleted, "", time.Now().UTC()); err != nil {
		o.failSubmission(ctx, &sub, err.Error())
		return
	}
	if err := o.store.PutSubmission(ctx, completedSub); err != nil && !errors.Is(err, ErrStaleAttempt) {
		o.failSubmission(ctx, &sub, fmt.Sprintf("persist completed state: %v", err))
	}
}

// startLeaseHeartbeat renews the submission lease every leaseDuration/3 and
// tracks a local leaseDeadline. This keeps multi-minute local binary analyses
// alive for their full duration while ensuring a worker cancels immediately if
// it loses database connectivity past its lease window.
func (o *Orchestrator) startLeaseHeartbeat(execCtx context.Context, cancelExec context.CancelFunc, sub api.Submission, leaseLost *atomic.Bool) func() {
	interval := o.leaseDuration / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		leaseDeadline := time.Now().UTC().Add(o.leaseDuration)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-execCtx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				if !now.Before(leaseDeadline) {
					leaseLost.Store(true)
					cancelExec()
					return
				}
				renewCtx, cancelRenew := context.WithDeadline(execCtx, leaseDeadline)
				err := o.store.RenewLease(renewCtx, sub.ID, sub.Attempts, now, o.leaseDuration)
				cancelRenew()
				if err == nil {
					leaseDeadline = time.Now().UTC().Add(o.leaseDuration)
					continue
				}
				if errors.Is(err, ErrStaleAttempt) || !time.Now().UTC().Before(leaseDeadline) {
					leaseLost.Store(true)
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
