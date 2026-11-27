// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// The lease contract checks two lease rules. Like the store contract, it
// runs against the memory store, SQLite, and (see postgres_test.go)
// PostgreSQL.
//
//  1. RenewLease never moves a lease back.
//  2. DelayRetry sets the lease, and may move it back.

func TestLeaseContractMemory(t *testing.T) { runLeaseContract(t, NewMemoryStore()) }

func TestLeaseContractSQLite(t *testing.T) {
	store, err := OpenStore("file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "lease.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runLeaseContract(t, store)
}

// runLeaseContract needs an empty store. All times are whole seconds apart.
// That is far more than the few milliseconds the test itself takes, which
// matters on PostgreSQL, where the lease follows the database's real clock.
func runLeaseContract(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	at := func(seconds int) time.Time { return now.Add(time.Duration(seconds) * time.Second) }
	// claimable reports whether a claim made at the given time gets the row.
	claimable := func(seconds int) (api.Submission, bool) {
		t.Helper()
		sub, ok, err := store.ClaimNextSubmission(ctx, at(seconds), time.Minute, 3)
		if err != nil {
			t.Fatalf("ClaimNextSubmission failed: %v", err)
		}
		return sub, ok
	}

	sub := api.Submission{SchemaVersion: api.SchemaVersionV1, ID: api.NewID("submission"), Status: api.SubmissionAccepted, AcceptedAt: now, Artifact: api.ArtifactInput{PURL: "pkg:npm/lease@1.0.0"}}
	if err := store.PutSubmission(ctx, sub); err != nil {
		t.Fatal(err)
	}
	// Claimed at second 0 for one minute. The lease ends at second 60.
	if _, ok := claimable(0); !ok {
		t.Fatal("expected the first claim to succeed")
	}
	// Renewed at second 30. The lease now ends at second 90.
	if err := store.RenewLease(ctx, sub.ID, 1, at(30), time.Minute); err != nil {
		t.Fatalf("RenewLease failed: %v", err)
	}

	// Rule 1. A renewal sent at second 10 arrives late. On its own it would
	// end at second 70. It is accepted, but it must not shorten the lease.
	if err := store.RenewLease(ctx, sub.ID, 1, at(10), time.Minute); err != nil {
		t.Fatalf("a late RenewLease must still be accepted, got %v", err)
	}
	if _, ok := claimable(80); ok {
		t.Fatal("a late renewal moved the lease back: the row was claimable at second 80")
	}

	// Rule 2. A retry delay of 5 seconds, set at second 30, ends at second
	// 35. That is earlier than the lease, and DelayRetry must allow it.
	if err := store.DelayRetry(ctx, sub.ID, 2, at(30), 5*time.Second); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("expected ErrStaleAttempt for the wrong attempt, got %v", err)
	}
	if err := store.DelayRetry(ctx, sub.ID, 1, at(30), 5*time.Second); err != nil {
		t.Fatalf("DelayRetry failed: %v", err)
	}
	if _, ok := claimable(33); ok {
		t.Fatal("the row was claimable before the retry delay was over")
	}
	second, ok := claimable(37)
	if !ok || second.ID != sub.ID || second.Attempts != 2 {
		t.Fatalf("expected attempt 2 once the retry delay was over, got ok=%v %+v", ok, second)
	}
	// The old attempt is fenced from now on.
	if err := store.DelayRetry(ctx, sub.ID, 1, at(40), time.Second); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("expected ErrStaleAttempt for the old attempt, got %v", err)
	}
}

// TestPostgresLeaseArgOnlySendsDurations checks what the PostgreSQL store
// takes from the gateway's clock: the AGE of a clock reading, and no date.
// That is what makes gateway clock differences harmless. The test needs no
// database.
func TestPostgresLeaseArgOnlySendsDurations(t *testing.T) {
	store := &SQLStore{postgres: true}
	near := func(got any, want float64) bool {
		seconds, ok := got.(float64)
		return ok && math.Abs(seconds-want) < 1
	}
	// A reading taken just now, plus one minute: add about 60 seconds.
	if got := store.leaseArg(time.Now(), time.Minute); !near(got, 60) {
		t.Fatalf("expected about 60 seconds, got %v", got)
	}
	// A reading that is 10 seconds old: add about 60 - 10 seconds.
	if got := store.leaseArg(time.Now().Add(-10*time.Second), time.Minute); !near(got, 50) {
		t.Fatalf("expected about 50 seconds, got %v", got)
	}
	// SQLite has no clock of its own, so it gets the time itself, as text.
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := (&SQLStore{}).leaseArg(at, time.Minute); got != "2026-01-02T03:05:05.000000000Z" {
		t.Fatalf("expected the SQLite lease as text, got %v", got)
	}
}
