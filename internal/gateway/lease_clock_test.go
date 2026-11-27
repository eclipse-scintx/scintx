// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

func TestMemoryLeaseKeepsMonotonicClock(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/clock@1.0.0"},
	}
	if err := store.PutSubmission(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := store.ClaimNextSubmission(context.Background(), now, time.Minute, 3)
	if err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	lease := store.submissions[claimed.ID].leaseUntil
	// == sees the monotonic reading. Equal does not. Round(0) strips it.
	// A lease that compares equal to its stripped form dropped the stopwatch,
	// and a wall-clock step can then expire it while the worker is still running.
	// The linter suggests Equal here. Equal would make this test pass for
	// every lease, so == stays.
	if lease == lease.Round(0) { //nolint:staticcheck // QF1009: == is on purpose, see above.
		t.Fatal("memory lease dropped the monotonic clock")
	}
}

func TestLeaseDeadlineReached(t *testing.T) {
	deadline := time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC)
	before := deadline.Add(-time.Second)
	after := deadline.Add(time.Second)
	if leaseDeadlineReached(before, deadline, true) {
		t.Fatal("a time before the deadline must not stop the worker")
	}
	if !leaseDeadlineReached(after, deadline, true) {
		t.Fatal("a wall time past the deadline must stop a SQLite worker")
	}
	if !leaseDeadlineReached(after, deadline, false) {
		t.Fatal("a time past the deadline must stop the worker")
	}
}

func TestSQLiteClaimUpdateDoesNotReviveCompletedRow(t *testing.T) {
	store, err := OpenSQLStore("file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "revive.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    time.Now().UTC(),
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/revive@1.0.0"},
	}
	if err := store.PutSubmission(ctx, sub); err != nil {
		t.Fatal(err)
	}
	// The row is finished. attempts stays 0, which is what a claim that
	// already read this row would use in its WHERE clause.
	if _, err := store.db.ExecContext(ctx, `UPDATE submissions SET status = 'completed' WHERE id = ?`, sub.ID); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	lease := formatTimestampUTC(now.Add(time.Minute))
	// Same predicate as claimOneCandidate. A claim that lost the race must
	// change no row.
	res, err := store.db.ExecContext(ctx, claimUpdateSQLite,
		"running", 1, lease, nil, `{}`, sub.ID, 0, formatTimestampUTC(now),
	)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("claim update revived a completed row (%d rows)", rows)
	}
	var status string
	if err := store.db.QueryRowContext(ctx, `SELECT status FROM submissions WHERE id = ?`, sub.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("status = %q, want completed", status)
	}
}
