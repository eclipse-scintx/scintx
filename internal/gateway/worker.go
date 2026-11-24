// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"time"
)

// This file holds the worker pool loop. It was split out of orchestrator.go
// to keep each file small. The worker goroutines only READ orchestrator
// settings (leaseDuration, maxAttempts, execHook). Those settings must be
// final before the workers start, which newOrchestrator guarantees.

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

// signalWake nudges one idle worker without blocking the caller.
func (o *Orchestrator) signalWake() {
	select {
	case o.wakeCh <- struct{}{}:
	default:
	}
}

// workerLoop claims and runs submissions until shutdown. It wakes on a
// signal from Submit or on the poll ticker (to pick up expired leases).
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
