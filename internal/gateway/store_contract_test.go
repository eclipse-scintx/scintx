// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// The store contract is one set of checks that every Store must pass. It runs
// against the memory store, SQLite, and (see postgres_test.go) PostgreSQL.
// One shared contract keeps the backends from drifting apart. That drift is
// how the SQL store came to allow "running -> accepted" while the memory
// store refused it.

func TestStoreContractMemory(t *testing.T) { runStoreContract(t, NewMemoryStore()) }

func TestStoreContractSQLite(t *testing.T) {
	store, err := OpenStore("file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "contract.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runStoreContract(t, store)
}

// runStoreContract needs an empty store.
func runStoreContract(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	newSub := func(purl string, at time.Time) api.Submission {
		return api.Submission{SchemaVersion: api.SchemaVersionV1, ID: api.NewID("submission"), Status: api.SubmissionAccepted, AcceptedAt: at, Artifact: api.ArtifactInput{PURL: purl}}
	}
	claim := func(at time.Time) (api.Submission, bool) {
		t.Helper()
		sub, ok, err := store.ClaimNextSubmission(ctx, at, time.Minute, 3)
		if err != nil {
			t.Fatalf("ClaimNextSubmission failed: %v", err)
		}
		return sub, ok
	}

	// Insert the newer submission first to prove claims go oldest-first.
	first := newSub("pkg:npm/first@1.0.0", now)
	second := newSub("pkg:npm/second@1.0.0", now.Add(time.Millisecond))
	for _, sub := range []api.Submission{second, first} {
		if err := store.PutSubmission(ctx, sub); err != nil {
			t.Fatalf("PutSubmission failed: %v", err)
		}
	}
	if err := store.PutSubmission(ctx, first); err == nil {
		t.Fatal("expected a duplicate submission ID to fail closed")
	}

	c1, ok := claim(now)
	if !ok || c1.ID != first.ID || c1.Status != api.SubmissionRunning || c1.Attempts != 1 {
		t.Fatalf("expected the oldest submission claimed as running attempt 1, got ok=%v %+v", ok, c1)
	}

	// A claimed submission must never go back to "accepted".
	back := c1
	back.Status = api.SubmissionAccepted
	if err := store.PutSubmission(ctx, back); err == nil {
		t.Fatal("expected running -> accepted to be refused")
	}
	if got, _, _ := store.GetSubmission(ctx, first.ID); got.Status != api.SubmissionRunning {
		t.Fatalf("expected status to stay running, got %q", got.Status)
	}

	// Lease renewal is fenced by the attempt number.
	if err := store.RenewLease(ctx, first.ID, 2, now, time.Minute); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("expected ErrStaleAttempt for the wrong attempt, got %v", err)
	}
	if err := store.RenewLease(ctx, first.ID, 1, now, time.Minute); err != nil {
		t.Fatalf("RenewLease failed: %v", err)
	}

	// A running -> running write (used to record a shutdown interruption)
	// must keep the lease. So the next claim returns the second submission.
	c1.Interruptions = 1
	if err := store.PutSubmission(ctx, c1); err != nil {
		t.Fatalf("running -> running PutSubmission failed: %v", err)
	}
	c2, ok := claim(now)
	if !ok || c2.ID != second.ID {
		t.Fatalf("expected the second submission, got ok=%v %+v", ok, c2)
	}
	if _, ok := claim(now); ok {
		t.Fatal("expected nothing claimable while both leases are active")
	}

	// Releasing the lease makes the first one claimable again at once.
	if err := store.ReleaseLease(ctx, first.ID, 1); err != nil {
		t.Fatalf("ReleaseLease failed: %v", err)
	}
	reclaimed, ok := claim(now)
	if !ok || reclaimed.ID != first.ID || reclaimed.Attempts != 2 || reclaimed.Interruptions != 1 {
		t.Fatalf("expected the first submission as attempt 2 with 1 interruption, got ok=%v %+v", ok, reclaimed)
	}

	// A late result from attempt 1 is fenced. Attempt 2 may complete.
	stale := c1
	_ = stale.TransitionTo(api.SubmissionCompleted, "", now)
	if err := store.PutSubmission(ctx, stale); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("expected ErrStaleAttempt for the stale attempt, got %v", err)
	}
	_ = reclaimed.TransitionTo(api.SubmissionCompleted, "", now)
	if err := store.PutSubmission(ctx, reclaimed); err != nil {
		t.Fatalf("completing the current attempt failed: %v", err)
	}
	done := reclaimed
	done.Status = api.SubmissionFailed
	done.Error = "late failure"
	if err := store.PutSubmission(ctx, done); err == nil {
		t.Fatal("expected a terminal submission to refuse further changes")
	}

	// Attempt cap: the second submission's lease expires again and again.
	// Claims 2 and 3 succeed. The next one marks it failed instead.
	for attempt := 2; attempt <= 3; attempt++ {
		later := now.Add(time.Duration(attempt) * time.Hour)
		if sub, ok := claim(later); !ok || sub.ID != second.ID || sub.Attempts != attempt {
			t.Fatalf("expected attempt %d of the second submission, got ok=%v %+v", attempt, ok, sub)
		}
	}
	if _, ok := claim(now.Add(10 * time.Hour)); ok {
		t.Fatal("expected no claim once the attempt cap is reached")
	}
	final, _, _ := store.GetSubmission(ctx, second.ID)
	if final.Status != api.SubmissionFailed || !strings.Contains(final.Error, "maximum execution attempts") || final.CompletedAt == nil {
		t.Fatalf("expected the exhausted submission to be failed, got %+v", final)
	}
}
