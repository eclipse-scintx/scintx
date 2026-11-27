// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds the lease heartbeat. It was split out of execution.go to
// keep each file small.

// leaseDeadlineReached reports whether this worker must stop.
//
// now.Before(deadline) uses the monotonic stopwatch when both times have
// one. PostgreSQL and the memory store follow that stopwatch, so a wall-clock
// step does not expire the lease.
//
// followWall is set for SQLite. Its lease is a wall-clock string, so a
// forward step expires the row while the stopwatch still has time left.
// The worker stops on that wall time too. Otherwise a second worker claims
// the submission this one is still running.
func leaseDeadlineReached(now, deadline time.Time, followWall bool) bool {
	if !now.Before(deadline) {
		return true
	}
	if !followWall {
		return false
	}
	// Round(0) drops the monotonic reading, so this comparison is the wall
	// clock alone. That is the clock SQLite stored.
	return !now.Round(0).Before(deadline.Round(0))
}

// storeFollowsWallClock reports whether o.store expires leases on wall time.
// Stores that do not implement WallClockLeases (memory, test fakes) keep
// the monotonic clock, and the answer is false.
func (o *Orchestrator) storeFollowsWallClock() bool {
	type wallClockLeases interface{ WallClockLeases() bool }
	w, ok := o.store.(wallClockLeases)
	return ok && w.WallClockLeases()
}

// startLeaseHeartbeat renews the submission lease every leaseDuration/3 and
// tracks a local leaseDeadline. This keeps multi-minute local binary analyses
// alive for their full duration while ensuring a worker cancels immediately if
// it loses database connectivity past its lease window.
//
// claimedAt is the time the store used when it set the first lease. The
// returned stop function is safe to call more than once.
func (o *Orchestrator) startLeaseHeartbeat(execCtx context.Context, cancelExec context.CancelFunc, sub api.Submission, claimedAt time.Time, leaseLost *atomic.Bool) func() {
	interval := o.leaseDuration / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The local deadline must never be LATER than the lease in the
		// database. If it were, this worker could keep running after another
		// worker was already allowed to claim the submission.
		//
		// So it starts from claimedAt, not from "now". The old code used the
		// time this goroutine started, which is later by however long the
		// claim query took.
		//
		// The rule "at most one worker holds an unexpired lease" depends
		// on this. It breaks if the deadline is taken from a fresh clock
		// reading instead.
		leaseDeadline := claimedAt.Add(o.leaseDuration)
		// Read once. The store does not change for the life of this worker.
		followWall := o.storeFollowsWallClock()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-execCtx.Done():
				return
			case <-ticker.C:
				// No UTC() on these clock readings: it would strip the
				// monotonic part. With it, the deadline check below still
				// works if the wall clock is set to a new time.
				now := time.Now()
				if leaseDeadlineReached(now, leaseDeadline, followWall) {
					leaseLost.Store(true)
					cancelExec()
					return
				}
				// The renewal must not outlive the lease, so its context
				// ends at leaseDeadline.
				renewCtx, cancelRenew := context.WithDeadline(execCtx, leaseDeadline)
				err := o.store.RenewLease(renewCtx, sub.ID, sub.Attempts, now, o.leaseDuration)
				cancelRenew()
				if err == nil {
					// Same rule as above. The store set the lease to
					// now + leaseDuration, with "now" taken BEFORE the call.
					// The old code took a fresh time after the call, which
					// was later by the round-trip time of the renewal.
					leaseDeadline = now.Add(o.leaseDuration)
					continue
				}
				if errors.Is(err, ErrStaleAttempt) || leaseDeadlineReached(time.Now(), leaseDeadline, followWall) {
					leaseLost.Store(true)
					cancelExec()
					return
				}
				// A canceled context is shutdown, which the loop exits for
				// on its own. Anything else is a storage problem. Say so.
				// The next tick tries again until the deadline.
				if !errors.Is(err, context.Canceled) {
					slog.Warn("lease renewal failed; will retry until the deadline",
						"id", sub.ID, "attempt", sub.Attempts, "error", err)
				}
			}
		}
	}()
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			close(done)
			cancelExec()
			wg.Wait()
		})
	}
}
