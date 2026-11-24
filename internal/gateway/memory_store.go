// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
)

type memoryEntry struct {
	sub        api.Submission
	leaseUntil time.Time
}

// MemoryStore provides thread-safe in-memory storage with lease-based claiming,
// deterministic FIFO ordering, and attempt fencing.
type MemoryStore struct {
	mu          sync.RWMutex
	submissions map[string]memoryEntry
}

// NewMemoryStore creates a new in-memory gateway store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		submissions: make(map[string]memoryEntry),
	}
}

// PutSubmission stores a new submission or updates an existing record in memory.
// It enforces the submission state machine and attempt fencing token so new
// submissions cannot overwrite existing IDs and stale attempts are rejected.
func (s *MemoryStore) PutSubmission(_ context.Context, sub api.Submission) error {
	if !sub.Status.IsValid() {
		return fmt.Errorf("invalid submission status %q", sub.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, exists := s.submissions[sub.ID]
	var from api.SubmissionStatus
	if exists {
		from = prev.sub.Status
		if prev.sub.Attempts != sub.Attempts {
			return fmt.Errorf("%w: submission %s is at attempt %d, got %d", ErrStaleAttempt, sub.ID, prev.sub.Attempts, sub.Attempts)
		}
	}
	if !api.CanTransition(from, sub.Status) {
		return fmt.Errorf("invalid submission state transition for %s: %q -> %q", sub.ID, from, sub.Status)
	}
	var lease time.Time
	if exists && !sub.Status.IsTerminal() {
		lease = prev.leaseUntil
	}
	s.submissions[sub.ID] = memoryEntry{sub: sub, leaseUntil: lease}
	return nil
}

// ClaimNextSubmission atomically claims the oldest eligible "accepted" or
// lease-expired "running" submission in memory, ordered by AcceptedAt.
func (s *MemoryStore) ClaimNextSubmission(_ context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUTC := now.UTC()
	for {
		var (
			bestID    string
			bestEntry memoryEntry
			found     bool
		)
		// Select the oldest claimable submission by AcceptedAt timestamp.
		for id, entry := range s.submissions {
			if entry.sub.Status.IsTerminal() {
				continue
			}
			if !entry.leaseUntil.IsZero() && entry.leaseUntil.After(nowUTC) {
				continue
			}
			if !found || entry.sub.AcceptedAt.Before(bestEntry.sub.AcceptedAt) ||
				(entry.sub.AcceptedAt.Equal(bestEntry.sub.AcceptedAt) && id < bestID) {
				bestID = id
				bestEntry = entry
				found = true
			}
		}
		if !found {
			return api.Submission{}, false, nil
		}

		sub := bestEntry.sub
		if sub.Attempts >= maxAttempts {
			reason := fmt.Sprintf("submission exceeded maximum execution attempts (%d)", maxAttempts)
			if err := sub.TransitionTo(api.SubmissionFailed, reason, nowUTC); err != nil {
				return api.Submission{}, false, err
			}
			s.submissions[bestID] = memoryEntry{sub: sub}
			continue
		}

		if err := sub.TransitionTo(api.SubmissionRunning, "", nowUTC); err != nil {
			return api.Submission{}, false, err
		}
		sub.Attempts++
		s.submissions[bestID] = memoryEntry{
			sub:        sub,
			leaseUntil: nowUTC.Add(leaseDuration),
		}
		return sub, true, nil
	}
}

// RenewLease extends the lease for an active attempt in memory.
func (s *MemoryStore) RenewLease(_ context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.submissions[id]
	if !exists || entry.sub.Status != api.SubmissionRunning || entry.sub.Attempts != attempt {
		return fmt.Errorf("%w: cannot renew lease for %s at attempt %d", ErrStaleAttempt, id, attempt)
	}
	entry.leaseUntil = now.UTC().Add(leaseDuration)
	s.submissions[id] = entry
	return nil
}

// ReleaseLease clears the active lease for an interrupted attempt in memory so
// another worker can immediately claim the submission without waiting.
func (s *MemoryStore) ReleaseLease(_ context.Context, id string, attempt int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.submissions[id]
	if !exists || entry.sub.Status != api.SubmissionRunning || entry.sub.Attempts != attempt {
		return fmt.Errorf("%w: cannot release lease for %s at attempt %d", ErrStaleAttempt, id, attempt)
	}
	entry.leaseUntil = time.Time{}
	s.submissions[id] = entry
	return nil
}

// GetSubmission retrieves a submission by ID from memory.
func (s *MemoryStore) GetSubmission(_ context.Context, id string) (api.Submission, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.submissions[id]
	return entry.sub, ok, nil
}

// Ping always succeeds for an in-memory store.
func (s *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// Close is a no-op for an in-memory store.
func (s *MemoryStore) Close() error {
	return nil
}
