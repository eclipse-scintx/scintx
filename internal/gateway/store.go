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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
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

// ErrStaleAttempt is returned when a worker attempts to renew a lease or write
// results for a submission whose attempt counter has moved on (fencing token).
var ErrStaleAttempt = errors.New("stale submission attempt fenced")

// ErrRetryable wraps transient adapter errors (such as HTTP 429/503 or temporary
// subprocess resource failures) so the worker releases the lease and retries up
// to maxAttempts instead of failing permanently on the first attempt.
var ErrRetryable = errors.New("retryable submission execution error")

// Store abstracts submission persistence and lease-based work claiming across
// SQLite, PostgreSQL, and in-memory backends.
type Store interface {
	// PutSubmission inserts a new submission or transitions an existing one.
	// It verifies both state transition validity and the attempt fencing token.
	PutSubmission(ctx context.Context, sub api.Submission) error
	// ClaimNextSubmission atomically claims the next eligible submission whose
	// status is "accepted" or "running" with an expired (or unset) lease.
	ClaimNextSubmission(ctx context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error)
	// RenewLease extends the lease_until timestamp for an in-flight "running"
	// submission owned by the given attempt number.
	RenewLease(ctx context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error
	// ReleaseLease clears the active lease_until timestamp for an in-flight
	// "running" submission when a worker is interrupted by shutdown or encounters
	// a transient ErrRetryable failure.
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

func ensureSQLiteDir(dsn string) error {
	path := strings.TrimPrefix(strings.TrimSpace(dsn), "file:")
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path == "" || path == ":memory:" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
