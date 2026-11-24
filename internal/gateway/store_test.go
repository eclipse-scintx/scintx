// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
)

func TestSQLStorePersistenceAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "scintx.db")
	dsn := "file:" + filepath.ToSlash(dbPath)
	ctx := context.Background()

	// 1. Open store and write a submission.
	store1, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore(1) failed: %v", err)
	}
	if err := store1.Ping(ctx); err != nil {
		t.Fatalf("Ping(1) failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            "submission-persist-001",
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	}
	if err := store1.PutSubmission(ctx, sub); err != nil {
		t.Fatalf("PutSubmission(accepted) failed: %v", err)
	}

	// Update submission to completed and close store (simulating restart).
	doneAt := now.Add(25 * time.Millisecond)
	sub.Status = api.SubmissionCompleted
	sub.CompletedAt = &doneAt
	if err := store1.PutSubmission(ctx, sub); err != nil {
		t.Fatalf("PutSubmission(completed) failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close(1) failed: %v", err)
	}

	// 2. Reopen store against the same SQLite file and verify persistence.
	store2, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore(2) failed: %v", err)
	}
	defer store2.Close()

	loaded, ok, err := store2.GetSubmission(ctx, sub.ID)
	if err != nil {
		t.Fatalf("GetSubmission failed: %v", err)
	}
	if !ok {
		t.Fatal("expected submission to persist across store reopen")
	}
	if loaded.Status != api.SubmissionCompleted || loaded.Artifact.PURL != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("unexpected loaded submission: %+v", loaded)
	}
}
