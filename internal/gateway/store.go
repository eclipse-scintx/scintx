// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package gateway manages artifact submissions, persistent storage, and status
// tracking.
package gateway

import (
	"context"
	"strings"
	"sync"

	"github.com/yeeth-security/scintx/api"
)

// Store abstracts submission persistence across SQLite, PostgreSQL, and
// in-memory test backends.
type Store interface {
	// PutSubmission inserts or updates a submission record.
	PutSubmission(ctx context.Context, sub api.Submission) error
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
	if trimmed == "" || strings.EqualFold(trimmed, "memory") || trimmed == ":memory:" {
		return NewMemoryStore(), nil
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

// PutSubmission stores or updates a submission record in memory.
func (s *MemoryStore) PutSubmission(_ context.Context, sub api.Submission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// Ping always succeeds for an in-memory store.
func (s *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// Close is a no-op for an in-memory store.
func (s *MemoryStore) Close() error {
	return nil
}
