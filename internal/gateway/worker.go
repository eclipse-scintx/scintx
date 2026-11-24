// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// This file holds the worker pool loop. It was split out of orchestrator.go
// to keep each file small. The worker goroutines only READ orchestrator
// settings (leaseDuration, maxAttempts, execHook). Those settings must be
// final before the workers start, which newOrchestrator guarantees.

// claimErrorLogInterval is the shortest gap between two "claim failed" log
// lines. A claim is retried on every poll tick and on every new submission,
// so an unthrottled log would flood during a database outage. (This comment
// used to say "every idle worker retries about ten times per second". That
// is no longer true: see pollLoop.)
const claimErrorLogInterval = 5 * time.Second

// defaultPollInterval is how often the gateway looks for work that became
// claimable without a wake signal. There are three such cases:
//
//  1. A retry whose backoff has run out (DefaultRetryBackoff, 5 seconds).
//  2. A lease that expired because its worker died (DefaultLeaseDuration,
//     30 seconds).
//  3. A submission that another gateway accepted, when several gateways
//     share one database.
//
// It used to be 100 milliseconds. One second is small next to the 5 and 30
// seconds above, and it means ten times fewer empty claim transactions. The
// price: work of these three kinds can start up to one second later. A new
// submission on this gateway is not affected. Submit wakes a worker at once.
const defaultPollInterval = time.Second

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
	// claimedAt is the "now" the store uses to set the lease. The heartbeat
	// gets the same value, so its local deadline matches the stored lease.
	//
	// No UTC() here on purpose. UTC() would strip the monotonic part of the
	// reading. With it, "how long ago was this" stays correct even if the
	// wall clock is set to a new time in between. The heartbeat and the
	// PostgreSQL store both measure exactly that (see leaseArg).
	claimedAt := time.Now()
	sub, ok, err := o.store.ClaimNextSubmission(ctx, claimedAt, o.leaseDuration, o.maxAttempts)
	if err != nil {
		// This error used to be dropped, so a database outage was invisible.
		o.logClaimError(err)
		return false
	}
	if !ok {
		return false
	}
	// Cascade wake signal so another idle worker immediately claims the next
	// queued submission while this worker executes sub.
	o.signalWake()
	o.ExecuteClaimedSubmission(ctx, sub, claimedAt)
	return true
}

// logClaimError reports a failed claim, at most once per claimErrorLogInterval.
// A canceled context is normal during shutdown, so it is not logged.
func (o *Orchestrator) logClaimError(err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	now := time.Now().UnixNano()
	last := o.lastClaimErrLog.Load()
	if last != 0 && now-last < int64(claimErrorLogInterval) {
		return
	}
	// CompareAndSwap lets exactly one of several racing workers write the line.
	if o.lastClaimErrLog.CompareAndSwap(last, now) {
		slog.Error("claim next submission failed; workers will keep retrying", "error", err)
	}
}

// signalWake nudges one idle worker without blocking the caller.
func (o *Orchestrator) signalWake() {
	select {
	case o.wakeCh <- struct{}{}:
	default:
	}
}

// workerLoop claims and runs submissions until shutdown. It wakes on a wake
// signal. The signal comes from Submit (new work), from another worker that
// just claimed something (there may be more), or from pollLoop (the timer).
//
// Each worker used to have its own poll ticker here. Then every idle worker
// ran an empty claim transaction every 100 milliseconds: 160 per second on a
// 16-worker gateway with nothing to do. Now one pollLoop ticks for the whole
// gateway, and a worker only sleeps on wakeCh.
func (o *Orchestrator) workerLoop() {
	defer o.wg.Done()
	for {
		for o.claimAndExecuteOne(o.workerCtx, true) {
		}
		select {
		case <-o.stopCh:
			return
		case <-o.workerCtx.Done():
			return
		case <-o.wakeCh:
		}
	}
}

// pollLoop is the one timer of the gateway. On every tick it wakes ONE idle
// worker, which tries one claim. So an idle gateway runs one claim
// transaction per tick, no matter how many workers it has.
//
// One wake is enough even when a lot of work turns up at once. A worker that
// claims something calls signalWake before it starts the work (see
// claimAndExecuteOne). That wakes the next worker, and so on, until a claim
// finds nothing.
//
// If all workers are busy, nobody reads the signal. That is fine: a worker
// always tries to claim again right after it finishes, before it sleeps.
func (o *Orchestrator) pollLoop() {
	defer o.wg.Done()
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-o.stopCh:
			return
		case <-o.workerCtx.Done():
			return
		case <-ticker.C:
			o.signalWake()
		}
	}
}
