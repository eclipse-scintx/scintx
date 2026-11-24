// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package gateway manages artifact submissions, persistent storage, and status
// tracking.
package gateway

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// Store abstracts submission persistence across SQLite, PostgreSQL, and
// in-memory test backends. Implementations enforce valid submission state
// transitions and fail closed on invalid transitions.
type Store interface {
	// PutSubmission inserts a new submission or transitions an existing one.
	PutSubmission(ctx context.Context, sub api.Submission) error
	// GetSubmission retrieves a submission by ID.
	GetSubmission(ctx context.Context, id string) (api.Submission, bool, error)
	// FailIncompleteSubmissions marks any non-terminal ("accepted" or "running")
	// submissions as "failed" during startup recovery so interrupted runs never
	// remain stranded in an indeterminate state.
	FailIncompleteSubmissions(ctx context.Context, reason string) error
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

// MemoryStore provides thread-safe in-memory storage for unit tests.
type MemoryStore struct {
	mu          sync.RWMutex
	submissions map[string]api.Submission
}

// NewMemoryStore creates a new in-memory gateway store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		submissions: make(map[string]api.Submission),
	}
}

// PutSubmission stores or updates a submission record in memory, enforcing the
// submission state machine.
func (s *MemoryStore) PutSubmission(_ context.Context, sub api.Submission) error {
	if !sub.Status.IsValid() {
		return fmt.Errorf("invalid submission status %q", sub.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, exists := s.submissions[sub.ID]
	var from api.SubmissionStatus
	if exists {
		from = prev.Status
	}
	if !api.CanTransition(from, sub.Status) {
		return fmt.Errorf("invalid submission state transition for %s: %q -> %q", sub.ID, from, sub.Status)
	}
	s.submissions[sub.ID] = sub
	return nil
}

// GetSubmission retrieves a submission by ID from memory.
func (s *MemoryStore) GetSubmission(_ context.Context, id string) (api.Submission, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.submissions[id]
	return sub, ok, nil
}

// FailIncompleteSubmissions transitions any non-terminal submissions to failed.
func (s *MemoryStore) FailIncompleteSubmissions(_ context.Context, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for id, sub := range s.submissions {
		if !sub.Status.IsTerminal() {
			if err := sub.TransitionTo(api.SubmissionFailed, reason, now); err != nil {
				return err
			}
			s.submissions[id] = sub
		}
	}
	return nil
}

// Ping always succeeds for an in-memory store.
func (s *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// Close is a no-op for an in-memory store.
func (s *MemoryStore) Close() error {
	return nil
}
