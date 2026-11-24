// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package gateway implements the SCINTX orchestration pipeline:
// provider selection, bounded concurrent execution, Aggregate Report
// generation, and Policy Report evaluation (#65, #68, #71-#75).
package gateway

import (
	"sync"

	"github.com/yeeth-security/scintx/api"
)

// Store persists submissions, Aggregate Reports, Policy Reports, and raw evidence blobs.
type Store struct {
	mu               sync.RWMutex
	submissions      map[string]api.Submission
	aggregateReports map[string]api.AggregateReport
	aggBySubmission  map[string]string
	policyReports    map[string]api.PolicyReport
	polBySubmission  map[string]string
	rawEvidence      map[string][]byte
}

// NewStore creates an initialized in-memory Store.
func NewStore() *Store {
	return &Store{
		submissions:      make(map[string]api.Submission),
		aggregateReports: make(map[string]api.AggregateReport),
		aggBySubmission:  make(map[string]string),
		policyReports:    make(map[string]api.PolicyReport),
		polBySubmission:  make(map[string]string),
		rawEvidence:      make(map[string][]byte),
	}
}

// PutSubmission saves or updates a Submission copy.
func (s *Store) PutSubmission(sub api.Submission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.submissions[sub.ID] = sub
}

// GetSubmission retrieves a Submission by ID.
func (s *Store) GetSubmission(id string) (api.Submission, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.submissions[id]
	return sub, ok
}

// PutAggregateReport stores an immutable AggregateReport and indexes it by submission ID.
func (s *Store) PutAggregateReport(rep api.AggregateReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aggregateReports[rep.ID] = rep
	s.aggBySubmission[rep.Submission.ID] = rep.ID
}

// GetAggregateReportBySubmission retrieves the AggregateReport for a submission ID.
func (s *Store) GetAggregateReportBySubmission(submissionID string) (api.AggregateReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	aggID, ok := s.aggBySubmission[submissionID]
	if !ok {
		return api.AggregateReport{}, false
	}
	rep, ok := s.aggregateReports[aggID]
	return rep, ok
}

// PutPolicyReport stores a PolicyReport and indexes it by submission ID.
func (s *Store) PutPolicyReport(rep api.PolicyReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyReports[rep.ID] = rep
	s.polBySubmission[rep.SubmissionID] = rep.ID
}

// GetPolicyReportBySubmission retrieves the PolicyReport for a submission ID.
func (s *Store) GetPolicyReportBySubmission(submissionID string) (api.PolicyReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	polID, ok := s.polBySubmission[submissionID]
	if !ok {
		return api.PolicyReport{}, false
	}
	rep, ok := s.policyReports[polID]
	return rep, ok
}

// PutRawEvidence stores raw provider response bytes and returns a reference ID (#68, #70).
func (s *Store) PutRawEvidence(data []byte) string {
	ref := api.NewID("evidence")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawEvidence[ref] = append([]byte(nil), data...)
	return ref
}
