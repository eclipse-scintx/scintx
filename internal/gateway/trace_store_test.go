// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds the recorder for the worker trace test (see
// trace_test.go). It records every store call that the workers make, so
// that the Lean model can judge them afterwards. How a call is written
// down is in trace_record_test.go.

// fault is what the recorder does to one store call.
type fault int

const (
	deliver fault = iota // The call reaches the store. The worker gets the answer.
	drop                 // The call never reaches the store. The worker gets an error.
	lose                 // The call reaches the store, but the worker gets an error.
	// slow holds the call back for a third of a lease, like a database that
	// answers slowly. The heartbeat must count its lease from the moment it
	// read the clock, not from the moment the answer came. Only a slow call
	// can show the difference: a call to the memory store is faster than
	// one step of the wall clock (which is coarse on Windows).
	slow
	// stall holds the call back for two lease durations before it reaches
	// the store. It stands for a hung connection or a frozen process. The
	// lease runs out in the meantime, so another worker takes over and the
	// late call is refused. This is the one way to make a correct worker
	// run into a refusal: otherwise it gives up at its own deadline first.
	stall
)

// errInjected is the error a worker gets for a dropped call or a lost answer.
var errInjected = errors.New("injected store fault")

// traceStore sits between the workers and a MemoryStore. It does two jobs:
//
//  1. It can break calls on purpose (drop, lose). A worker must behave
//     correctly through that too.
//  2. It writes down every call: what the worker sent, what the store did,
//     what the worker got back, and the row afterwards.
//
// One mutex is held across the whole of each call. So the order of the
// recording is exactly the order in which the store saw the calls.
type traceStore struct {
	Store // GetSubmission, Ping and Close go straight through.
	inner *MemoryStore
	// start is the real time that stands for time 0 in the model. It lies
	// one hour in the past, so that no recorded time is negative.
	start time.Time
	// plan decides the fault for each call. It runs under mu.
	plan func(call string) fault

	mu     sync.Mutex
	ids    []string            // Submission IDs, in the order they first appear.
	events map[string][]string // The recorded lines of each submission.
	counts map[string]int      // How often each kind of line was recorded.
}

func newTraceStore(plan func(call string) fault) *traceStore {
	inner := NewMemoryStore()
	return &traceStore{
		Store: inner,
		inner: inner,
		// Round(0) removes the monotonic part. All recorded times are then
		// plain wall-clock differences, like the times the store keeps.
		start:  time.Now().Round(0).Add(-time.Hour),
		plan:   plan,
		events: make(map[string][]string),
		counts: make(map[string]int),
	}
}

// call runs one store call of a worker, with the planned fault, and records it.
func (s *traceStore) call(ctx context.Context, id, name string, k int, at time.Time, delay time.Duration, send func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	planned := s.plan(name)
	if hold := map[fault]time.Duration{slow: traceLease / 3, stall: 2 * traceLease}[planned]; hold > 0 {
		// Wait without the lock, so that other workers can go on.
		s.mu.Unlock()
		time.Sleep(hold)
		s.mu.Lock()
	}
	if planned == drop {
		s.record(ctx, id, name, k, at, delay, "dropped", "error")
		return errInjected
	}
	err := send()
	arrival, answer := "accepted", "ok"
	switch {
	case errors.Is(err, ErrStaleAttempt):
		arrival, answer = "refused", "stale"
	case err != nil:
		arrival, answer = "refused", "error"
	}
	if planned == lose {
		answer, err = "error", errInjected
	}
	s.record(ctx, id, name, k, at, delay, arrival, answer)
	return err
}

// PutSubmission records the three writes a worker makes with it. A new
// submission ("accepted") is not a worker call, so it goes straight through.
func (s *traceStore) PutSubmission(ctx context.Context, sub api.Submission) error {
	var name string
	switch sub.Status {
	case api.SubmissionCompleted:
		name = "complete"
	case api.SubmissionFailed:
		name = "fail"
	case api.SubmissionRunning:
		name = "interrupt" // Only releaseForShutdown writes "running".
	default:
		return s.inner.PutSubmission(ctx, sub)
	}
	return s.call(ctx, sub.ID, name, sub.Attempts, time.Time{}, 0, func() error { return s.inner.PutSubmission(ctx, sub) })
}

func (s *traceStore) RenewLease(ctx context.Context, id string, attempt int, now time.Time, d time.Duration) error {
	return s.call(ctx, id, "renew", attempt, now, 0, func() error { return s.inner.RenewLease(ctx, id, attempt, now, d) })
}

func (s *traceStore) DelayRetry(ctx context.Context, id string, attempt int, now time.Time, delay time.Duration) error {
	return s.call(ctx, id, "delay", attempt, now, delay, func() error { return s.inner.DelayRetry(ctx, id, attempt, now, delay) })
}

func (s *traceStore) ReleaseLease(ctx context.Context, id string, attempt int) error {
	return s.call(ctx, id, "release", attempt, time.Time{}, 0, func() error { return s.inner.ReleaseLease(ctx, id, attempt) })
}

// ClaimNextSubmission records a claim. One call can change several rows: it
// marks every row that is out of attempts as failed ("exhaust"), and then
// claims one row ("claim"). Each changed row gets its own line.
func (s *traceStore) ClaimNextSubmission(ctx context.Context, now time.Time, d time.Duration, maxAttempts int) (api.Submission, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	planned := s.plan("claim")
	if planned == drop {
		return api.Submission{}, false, errInjected // No row was touched.
	}
	unfinished := s.unfinished()
	sub, ok, err := s.inner.ClaimNextSubmission(ctx, now, d, maxAttempts)
	answer := "ok"
	if planned == lose {
		answer = "error"
	}
	for _, id := range unfinished {
		if got, _, _ := s.inner.GetSubmission(ctx, id); got.Status == api.SubmissionFailed {
			s.record(ctx, id, "exhaust", 0, now, 0, "accepted", answer)
		}
	}
	if ok {
		s.record(ctx, sub.ID, "claim", sub.Attempts, now, 0, "accepted", answer)
	}
	if planned == lose {
		return api.Submission{}, false, errInjected
	}
	return sub, ok, err
}

// unfinished lists the submissions that are not completed or failed.
func (s *traceStore) unfinished() []string {
	s.inner.mu.RLock()
	defer s.inner.mu.RUnlock()
	var ids []string
	for id, entry := range s.inner.submissions {
		if !entry.sub.Status.IsTerminal() {
			ids = append(ids, id)
		}
	}
	return ids
}
