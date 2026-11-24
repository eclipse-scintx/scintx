// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package gateway manages artifact submissions and status tracking.
package gateway

import (
	"sync"

	"github.com/yeeth-security/scintx/api"
)

// Store provides thread-safe in-memory storage for submissions.
// State is retained in memory for the lifetime of the gateway process and
// cleared upon container or process restart.
type Store struct {
	mu          sync.RWMutex
	submissions map[string]api.Submission
}

// NewStore creates a new in-memory gateway store.
func NewStore() *Store {
	return &Store{
		submissions: make(map[string]api.Submission),
	}
}

// PutSubmission stores or updates a submission record.
func (s *Store) PutSubmission(sub api.Submission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submissions[sub.ID] = sub
}

// GetSubmission retrieves a submission by ID.
func (s *Store) GetSubmission(id string) (api.Submission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.submissions[id]
	return sub, ok
}
