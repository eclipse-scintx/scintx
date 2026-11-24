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

func TestSQLStorePersistenceAndStateMachine(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "scintx.db")
	dsn := "file:" + filepath.ToSlash(dbPath)
	ctx := context.Background()

	// 1. Open store and write a submission through valid state transitions.
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

	// Skipping "running" (accepted -> completed directly) must fail closed.
	invalidJump := sub
	invalidJump.Status = api.SubmissionCompleted
	if err := store1.PutSubmission(ctx, invalidJump); err == nil {
		t.Fatal("expected PutSubmission to reject accepted -> completed transition")
	}

	// Transition accepted -> running -> completed.
	if err := sub.TransitionTo(api.SubmissionRunning, "", now.Add(10*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store1.PutSubmission(ctx, sub); err != nil {
		t.Fatalf("PutSubmission(running) failed: %v", err)
	}
	if err := sub.TransitionTo(api.SubmissionCompleted, "", now.Add(25*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store1.PutSubmission(ctx, sub); err != nil {
		t.Fatalf("PutSubmission(completed) failed: %v", err)
	}

	// Also insert an interrupted submission left in "running" state before restart.
	stranded := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            "submission-stranded-002",
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/express@4.19.2"},
	}
	if err := store1.PutSubmission(ctx, stranded); err != nil {
		t.Fatal(err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close(1) failed: %v", err)
	}

	// 2. Reopen store: completed submission stays completed, stranded submission fails closed.
	store2, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore(2) failed: %v", err)
	}
	defer store2.Close()

	loaded, ok, err := store2.GetSubmission(ctx, sub.ID)
	if err != nil || !ok {
		t.Fatalf("GetSubmission(completed) failed: %v, ok=%v", err, ok)
	}
	if loaded.Status != api.SubmissionCompleted {
		t.Fatalf("expected completed, got %q", loaded.Status)
	}

	recovered, ok, err := store2.GetSubmission(ctx, stranded.ID)
	if err != nil || !ok {
		t.Fatalf("GetSubmission(stranded) failed: %v, ok=%v", err, ok)
	}
	if recovered.Status != api.SubmissionFailed || recovered.Error == "" {
		t.Fatalf("expected stranded submission to fail closed on reopen, got %+v", recovered)
	}
}
