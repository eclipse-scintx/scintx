// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds the lease methods of the memory store. They were split out
// of memory_store.go to keep each file small.

// updateLease changes the lease of a "running" submission that the given
// attempt owns. Every other caller is fenced with ErrStaleAttempt.
//
// next gets the stored lease and returns the new one. The zero time means
// "no lease". The three lease methods below only differ in that function.
func (s *MemoryStore) updateLease(id string, attempt int, action string, next func(current time.Time) time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.submissions[id]
	if !exists || entry.sub.Status != api.SubmissionRunning || entry.sub.Attempts != attempt {
		return fmt.Errorf("%w: cannot %s lease for %s at attempt %d", ErrStaleAttempt, action, id, attempt)
	}
	entry.leaseUntil = next(entry.leaseUntil)
	s.submissions[id] = entry
	return nil
}

// RenewLease extends the lease for an active attempt in memory.
//
// It never moves the lease back. A renewal that arrives late, after a newer
// one, must not shorten the lease (see the Store interface).
func (s *MemoryStore) RenewLease(_ context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error {
	renewed := now.UTC().Add(leaseDuration)
	return s.updateLease(id, attempt, "renew", func(current time.Time) time.Time {
		if current.After(renewed) {
			return current // The stored lease is later. Keep it.
		}
		return renewed
	})
}

// DelayRetry sets the lease to now + delay, so the next retry waits that
// long. It may move the lease back (see the Store interface).
func (s *MemoryStore) DelayRetry(_ context.Context, id string, attempt int, now time.Time, delay time.Duration) error {
	return s.updateLease(id, attempt, "delay retry of", func(time.Time) time.Time {
		return now.UTC().Add(delay)
	})
}

// ReleaseLease clears the active lease for an attempt that a graceful
// shutdown interrupted, so it can be claimed again at once.
func (s *MemoryStore) ReleaseLease(_ context.Context, id string, attempt int) error {
	return s.updateLease(id, attempt, "release", func(time.Time) time.Time {
		return time.Time{}
	})
}
