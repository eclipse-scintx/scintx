// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds the lease heartbeat. It was split out of execution.go to
// keep each file small.

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
		leaseDeadline := claimedAt.Add(o.leaseDuration)
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
					// Same rule as above. The store set the lease to
					// now + leaseDuration, with "now" taken BEFORE the call.
					// The old code took a fresh time after the call, which
					// was later by the round-trip time of the renewal.
					leaseDeadline = now.Add(o.leaseDuration)
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
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			close(done)
			cancelExec()
			wg.Wait()
		})
	}
}
