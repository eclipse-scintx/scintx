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
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// DefaultLeaseDuration is the short time window a worker holds a claim on a
// running submission. Active workers renew this lease every DefaultLeaseDuration/3
// so multi-minute tasks stay owned while crashed containers recover within 30s.
const DefaultLeaseDuration = 30 * time.Second

// DefaultMaxAttempts is the maximum number of execution claims allowed for a
// submission before it transitions to terminal "failed" state.
const DefaultMaxAttempts = 3

// DefaultMaxExecutionDuration bounds the total wall-clock time of a single
// submission execution attempt (15 minutes). This accommodates both fast remote
// HTTP polling tasks and multi-minute local binary analysis processes while
// still terminating hung tasks.
const DefaultMaxExecutionDuration = 15 * time.Minute

// DefaultRetryBackoff is the wait before the first retry of an attempt that
// failed with ErrRetryable. Each later retry waits twice as long (5s, 10s,
// and so on). Before this existed a retry ran at once, so a provider that
// answered "429 too many requests" used up every attempt within a millisecond.
const DefaultRetryBackoff = 5 * time.Second

// ErrStaleAttempt is returned when a worker attempts to renew a lease or write
// results for a submission whose attempt counter has moved on (fencing token).
var ErrStaleAttempt = errors.New("stale submission attempt fenced")

// ErrRetryable wraps transient adapter errors (such as HTTP 429/503 or temporary
// subprocess resource failures) so the worker retries after a backoff, up to
// maxAttempts, instead of failing permanently on the first attempt.
var ErrRetryable = errors.New("retryable submission execution error")

// Store abstracts submission persistence and lease-based work claiming across
// SQLite, PostgreSQL, and in-memory backends.
//
// About the "now" arguments: "now" is the caller's reading of its OWN clock,
// taken just before the call. A store without a clock of its own (memory,
// SQLite) uses it as it is. PostgreSQL has its own clock and uses that one
// instead, so that gateways with different clocks still agree on every
// lease. It only takes the AGE of the reading from the caller (see
// sql_lease.go). So pass time.Now(), and do not strip its monotonic part
// with UTC().
type Store interface {
	// PutSubmission inserts a new submission or transitions an existing one.
	// It verifies both state transition validity and the attempt fencing token.
	PutSubmission(ctx context.Context, sub api.Submission) error
	// ClaimNextSubmission atomically claims the next eligible submission whose
	// status is "accepted" or "running" with an expired (or unset) lease.
	ClaimNextSubmission(ctx context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error)
	// RenewLease extends the lease_until timestamp for an in-flight "running"
	// submission owned by the given attempt number.
	//
	// It only ever moves the lease FORWARD: the new lease is the later of
	// the stored lease and now + leaseDuration. It used to set the lease to
	// now + leaseDuration in every case. That had a flaw:
	// an old renewal that arrived after a newer one moved the lease back,
	// and a second worker could then claim the row too early.
	//
	// (The orchestrator used to call this to delay a retry as well. A retry
	// delay can be shorter than the current lease, so it now has its own
	// method, DelayRetry.)
	RenewLease(ctx context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error
	// DelayRetry sets lease_until to now + delay for a "running" submission
	// owned by the given attempt number. A lease in the future stops any
	// worker from claiming the row, so it works as a "not before" timer for
	// the next retry. Unlike RenewLease it may move the lease back. That is
	// safe because the caller has stopped working on the attempt.
	DelayRetry(ctx context.Context, id string, attempt int, now time.Time, delay time.Duration) error
	// ReleaseLease clears the active lease_until timestamp for an in-flight
	// "running" submission when a worker is interrupted by shutdown. The row
	// can then be claimed again at once. (Retryable failures no longer use
	// this. They wait out a backoff through RenewLease instead.)
	ReleaseLease(ctx context.Context, id string, attempt int) error
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
