// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package gateway manages artifact submissions, lease-based persistent storage,
// and self-healing status tracking.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// DefaultLeaseDuration is the time window a worker holds a claim on a
// running submission before another worker (or a restarted gateway) can
// automatically re-claim it if heartbeats stop.
const DefaultLeaseDuration = 30 * time.Second

// DefaultMaxAttempts is the maximum number of execution claims allowed for a
// submission before it transitions to terminal "failed" state (preventing
// infinite crash loops).
const DefaultMaxAttempts = 3

// ErrStaleAttempt is returned when a worker attempts to renew a lease or write
// results for a submission whose attempt counter has moved on (fencing token).
var ErrStaleAttempt = errors.New("stale submission attempt fenced")

// Store abstracts submission persistence and lease-based work claiming across
// SQLite, PostgreSQL, and in-memory backends.
type Store interface {
	// PutSubmission inserts a new submission or transitions an existing one,
	// verifying both state transition validity and the attempt fencing token.
	PutSubmission(ctx context.Context, sub api.Submission) error
	// ClaimNextSubmission atomically claims the next eligible submission whose
	// status is "accepted" or "running" with an expired (or unset) lease.
	ClaimNextSubmission(ctx context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error)
	// RenewLease extends the lease_until timestamp for an in-flight "running"
	// submission owned by the given attempt number. Returns ErrStaleAttempt if
	// the submission is no longer in "running" state at that attempt.
	RenewLease(ctx context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error
	// GetSubmission retrieves a submission by ID.
	GetSubmission(ctx context.Context, id string) (api.Submission, bool, error)
	// Ping verifies that the underlying storage backend is reachable.
	Ping(ctx context.Context) error
	// Close releases any underlying database connections.
	Close() error
}

// OpenStore opens a persistent SQLite or PostgreSQL store from dsn, or returns
// an in-memory store when dsn is "memory" or ":memory:".
func OpenStore(dsn string) (Store, error) {
	trimmed := strings.TrimSpace(dsn)
	if strings.EqualFold(trimmed, "memory") || trimmed == ":memory:" {
		return NewMemoryStore(), nil
	}
	if trimmed == "" {
		return nil, fmt.Errorf("storage DSN must not be empty")
	}
	return OpenSQLStore(trimmed)
}

type memoryEntry struct {
	sub        api.Submission
	leaseUntil time.Time
}

// MemoryStore provides thread-safe in-memory storage with lease-based claiming
// and attempt fencing.
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

// PutSubmission stores or updates a submission record in memory, enforcing the
// submission state machine and attempt fencing token.
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

// ClaimNextSubmission atomically claims an eligible "accepted" or lease-expired
// "running" submission in memory.
func (s *MemoryStore) ClaimNextSubmission(_ context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	nowUTC := now.UTC()
	for id, entry := range s.submissions {
		sub := entry.sub
		if sub.Status.IsTerminal() {
			continue
		}
		if !entry.leaseUntil.IsZero() && entry.leaseUntil.After(nowUTC) {
			continue
		}

		if sub.Attempts >= maxAttempts {
			reason := fmt.Sprintf("submission exceeded maximum execution attempts (%d)", maxAttempts)
			if err := sub.TransitionTo(api.SubmissionFailed, reason, nowUTC); err != nil {
				return api.Submission{}, false, err
			}
			s.submissions[id] = memoryEntry{sub: sub}
			continue
		}

		if err := sub.TransitionTo(api.SubmissionRunning, "", nowUTC); err != nil {
			return api.Submission{}, false, err
		}
		sub.Attempts++
		s.submissions[id] = memoryEntry{
			sub:        sub,
			leaseUntil: nowUTC.Add(leaseDuration),
		}
		return sub, true, nil
	}
	return api.Submission{}, false, nil
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
