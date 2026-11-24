// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds the final storage writes of one execution attempt:
// completed, failed, retry later, and released for shutdown. Every write
// logs its error. They used to be dropped, which hid storage problems.

// finalWriteTimeout bounds each of those final writes.
const finalWriteTimeout = 10 * time.Second

// finalWriteContext returns a fresh context for a final write.
//
// The worker context cannot be used here. During shutdown it is already
// canceled, yet the result of a finished attempt must still be saved. The
// timeout keeps a hung database from blocking shutdown forever.
func finalWriteContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), finalWriteTimeout)
}

// completeSubmission records a successful attempt as "completed".
func (o *Orchestrator) completeSubmission(sub api.Submission) {
	log := slog.With("id", sub.ID, "attempt", sub.Attempts)
	// Transition a copy so sub stays "running" if the transition is refused.
	completedSub := sub
	if err := completedSub.TransitionTo(api.SubmissionCompleted, "", time.Now().UTC()); err != nil {
		log.Error("cannot mark submission completed", "error", err)
		o.failSubmission(&sub, "internal execution error")
		return
	}
	ctx, cancel := finalWriteContext()
	defer cancel()
	err := o.store.PutSubmission(ctx, completedSub)
	switch {
	case err == nil:
		// The submission is finished and saved. Nobody needs its uploaded
		// bytes any more, so delete them right now.
		o.deleteContent(completedSub)
	case errors.Is(err, ErrStaleAttempt):
		log.Warn("completed result discarded: a newer attempt owns this submission")
	default:
		// Do NOT mark the submission failed here. The work succeeded and only
		// the save failed. The old code turned one brief database error into
		// a permanent "failed". Now the row stays "running", its lease runs
		// out, and a worker runs it again.
		log.Error("saving the completed result failed; the submission will run again after its lease expires", "error", err)
	}
}

// failSubmission records a terminal "failed" state with a public reason.
func (o *Orchestrator) failSubmission(sub *api.Submission, reason string) {
	if sub.Status.IsTerminal() {
		return
	}
	log := slog.With("id", sub.ID, "attempt", sub.Attempts)
	if err := sub.TransitionTo(api.SubmissionFailed, reason, time.Now().UTC()); err != nil {
		log.Error("cannot mark submission failed", "error", err)
		return
	}
	ctx, cancel := finalWriteContext()
	defer cancel()
	if err := o.store.PutSubmission(ctx, *sub); err != nil {
		if !errors.Is(err, ErrStaleAttempt) {
			log.Error("saving the failed state failed; the submission will run again after its lease expires", "error", err)
		}
		// Keep the uploaded bytes here. The failed state was not saved, so
		// this submission (or the newer attempt that owns it) still runs.
		return
	}
	// The failed state is saved and final. Delete the uploaded bytes now.
	o.deleteContent(*sub)
}

// scheduleRetry makes the submission claimable again after a backoff delay.
//
// DelayRetry sets lease_until to now + delay and leaves the row "running".
// No worker may claim a row whose lease is still in the future, so the lease
// works as a "not before" timer. When it runs out, the normal poll loop
// claims the row as the next attempt.
//
// The old code cleared the lease instead. The retry then ran at once, and a
// provider answering "429" used up every attempt within a millisecond.
//
// This used to call RenewLease. RenewLease now only moves a lease forward
// (see the Store interface), and a retry delay is often shorter than the
// lease that is left. So the delay has its own store method.
func (o *Orchestrator) scheduleRetry(sub api.Submission, cause error) {
	delay := o.retryDelay(sub)
	log := slog.With("id", sub.ID, "attempt", sub.Attempts)
	log.Warn("attempt failed with a retryable error; retrying after backoff", "retryIn", delay.String(), "error", cause)
	ctx, cancel := finalWriteContext()
	defer cancel()
	if err := o.store.DelayRetry(ctx, sub.ID, sub.Attempts, time.Now(), delay); err != nil {
		// Nothing more to do. The current lease still runs out by itself.
		log.Error("scheduling the retry failed; it will run when the current lease expires", "error", err)
	}
}

// releaseForShutdown hands a submission back when a graceful shutdown cut its
// attempt short. It does two things:
//
//  1. It adds one to Interruptions, so this attempt does not count toward
//     the attempt cap. Before, each deploy during a long scan used up one
//     attempt, and the third deploy failed the scan for good.
//  2. It clears the lease, so the next gateway instance can claim the
//     submission with no wait.
//
// These are two writes. If the first fails, the attempt simply counts as
// before. If the second fails, the lease runs out by itself.
func (o *Orchestrator) releaseForShutdown(sub api.Submission) {
	log := slog.With("id", sub.ID, "attempt", sub.Attempts)
	ctx, cancel := finalWriteContext()
	defer cancel()
	sub.Interruptions++
	if err := o.store.PutSubmission(ctx, sub); err != nil {
		if errors.Is(err, ErrStaleAttempt) {
			return // A newer attempt owns the submission. Leave it alone.
		}
		log.Warn("recording the shutdown interruption failed; this attempt will count toward the cap", "error", err)
	}
	if err := o.store.ReleaseLease(ctx, sub.ID, sub.Attempts); err != nil {
		log.Warn("releasing the lease on shutdown failed; it will expire by itself", "error", err)
	}
}
