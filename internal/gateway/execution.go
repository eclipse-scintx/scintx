// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// publicFailureReason is the text stored in the public "error" field when an
// execution hook fails. The hook's own error can hold upstream URLs, tokens,
// or internal host names, so it goes to the log only. Operators can match the
// log line to the submission by its id.
const publicFailureReason = "submission execution failed"

// ExecuteClaimedSubmission runs a claimed submission under a bounded per-attempt
// timeout while periodically renewing its lease every leaseDuration/3.
// claimedAt is the time passed to ClaimNextSubmission for this claim.
//
// The outcome is decided in this order:
//  1. Lease lost or fenced (ErrStaleAttempt or local leaseDeadline expired):
//     abort immediately without touching storage.
//  2. The hook returned nil: the work is done, so record "completed". This
//     comes before the shutdown and timeout checks on purpose. A run that
//     finished right at the deadline, or right as a shutdown began, used to
//     be thrown away or marked failed.
//  3. Parent context canceled (graceful shutdown timeout):
//     release the active lease immediately so the next gateway instance can
//     claim the submission with zero wait delay. The attempt is not counted.
//  4. Per-attempt execution timeout exceeded (maxExecutionDuration):
//     fail closed by transitioning the submission to "failed".
//  5. Transient retryable error (ErrRetryable) with remaining attempts:
//     retry after a backoff delay, up to maxAttempts.
//  6. Any other error: fail closed with a generic public reason.
func (o *Orchestrator) ExecuteClaimedSubmission(ctx context.Context, sub api.Submission, claimedAt time.Time) {
	maxDur := o.maxExecutionDuration
	if maxDur <= 0 {
		maxDur = DefaultMaxExecutionDuration
	}

	execCtx, cancelExec := context.WithTimeout(ctx, maxDur)
	var leaseLost atomic.Bool
	stopHeartbeat := o.startLeaseHeartbeat(execCtx, cancelExec, sub, claimedAt, &leaseLost)
	defer stopHeartbeat()

	log := slog.With("id", sub.ID, "attempt", sub.Attempts)
	defer func() {
		if r := recover(); r != nil {
			stopHeartbeat()
			// Always log a panic. It used to vanish when the lease was lost.
			// The panic value stays out of the public error field.
			log.Error("submission execution panicked", "panic", r, "stack", string(debug.Stack()))
			if !leaseLost.Load() {
				o.failSubmission(&sub, "internal execution error")
			}
		}
	}()

	var hookErr error
	if o.execHook != nil {
		// Attach OpenContent to a copy of the submission so provider adapters
		// can stream uploaded bytes via sub.Artifact.OpenContent() (#70).
		hookSub := sub
		if hookSub.Artifact.ContentMeta != nil && o.blobs != nil {
			id := hookSub.ID
			hookSub.Artifact.OpenContent = func() (io.ReadCloser, error) {
				return o.OpenContent(id)
			}
		}
		hookErr = o.execHook(execCtx, hookSub)
	}
	// Read the timeout state first: stopping the heartbeat cancels execCtx.
	timedOut := errors.Is(execCtx.Err(), context.DeadlineExceeded)
	// Stop the heartbeat before any final write. Otherwise a late renewal
	// could overwrite the lease that a retry or a shutdown release just set.
	// After this call leaseLost can no longer change.
	stopHeartbeat()

	switch {
	case leaseLost.Load() || errors.Is(hookErr, ErrStaleAttempt):
		log.Warn("lease lost; abandoning this attempt without writing a result")
	case hookErr == nil:
		o.completeSubmission(sub)
	case ctx.Err() != nil:
		o.releaseForShutdown(sub)
	case timedOut:
		log.Warn("submission execution timed out", "limit", maxDur.String())
		o.failSubmission(&sub, fmt.Sprintf("submission execution timed out after %s", maxDur))
	case errors.Is(hookErr, ErrRetryable) && !sub.AttemptsExhausted(o.maxAttempts):
		o.scheduleRetry(sub, hookErr)
	default:
		log.Error("submission execution failed", "error", hookErr)
		o.failSubmission(&sub, publicFailureReason)
	}
}

// maxBackoffDoublings caps the exponential retry delay at 64 times the base
// (5s * 64 is a little over five minutes with the default backoff).
const maxBackoffDoublings = 6

// retryDelay returns how long to wait before the next retry. The first
// counted attempt waits retryBackoff, the second twice that, and so on.
// Attempts cut short by a shutdown are not counted.
func (o *Orchestrator) retryDelay(sub api.Submission) time.Duration {
	doublings := sub.Attempts - sub.Interruptions - 1
	if doublings < 0 {
		doublings = 0
	}
	if doublings > maxBackoffDoublings {
		doublings = maxBackoffDoublings
	}
	return o.retryBackoff << doublings
}
