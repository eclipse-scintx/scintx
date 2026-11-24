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
	"github.com/yeeth-security/scintx/internal/config"
)

func TestSQLStoreLeaseRecoveryAndAttemptCap(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "scintx.db")
	dsn := "file:" + filepath.ToSlash(dbPath)
	ctx := context.Background()

	// 1. Open store and insert an "accepted" submission and an in-flight
	// "running" submission whose lease expires across a gateway restart.
	store1, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore(1) failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	inFlight := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            "submission-aa00bb11cc22",
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	}
	if err := store1.PutSubmission(ctx, inFlight); err != nil {
		t.Fatalf("PutSubmission(inFlight) failed: %v", err)
	}

	// Simulate worker claiming the submission with a short 10ms lease, then crashing before completion.
	claimed, ok, err := store1.ClaimNextSubmission(ctx, now, 10*time.Millisecond, 3)
	if err != nil || !ok {
		t.Fatalf("ClaimNextSubmission(1) failed: err=%v ok=%v", err, ok)
	}
	if claimed.Status != api.SubmissionRunning || claimed.Attempts != 1 {
		t.Fatalf("expected running with attempts=1, got %+v", claimed)
	}

	// While lease is still active (now + 2ms), another claim must NOT steal it.
	if _, ok, err := store1.ClaimNextSubmission(ctx, now.Add(2*time.Millisecond), 10*time.Millisecond, 3); err != nil || ok {
		t.Fatalf("expected active lease to prevent premature claim, got ok=%v err=%v", ok, err)
	}

	// Close store1 while submission is still "running" (simulating gateway crash/restart).
	if err := store1.Close(); err != nil {
		t.Fatalf("Close(1) failed: %v", err)
	}

	// 2. Wait for the 10ms lease to expire, start a new gateway Orchestrator on store2,
	// and verify it automatically picks the in-flight submission back up and completes it!
	time.Sleep(20 * time.Millisecond)

	store2, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore(2) failed: %v", err)
	}
	defer store2.Close()

	orch := NewOrchestrator(config.Default(), store2)
	defer orch.Shutdown()
	orch.Wait()

	recovered, ok, err := store2.GetSubmission(ctx, inFlight.ID)
	if err != nil || !ok {
		t.Fatalf("GetSubmission(recovered) failed: %v, ok=%v", err, ok)
	}
	if recovered.Status != api.SubmissionCompleted {
		t.Fatalf("expected restarted gateway to pick up and complete in-flight submission, got %+v", recovered)
	}
	if recovered.Attempts != 2 {
		t.Fatalf("expected attempts=2 after restart pickup, got %d", recovered.Attempts)
	}

	// 3. Verify that a submission that repeatedly fails/expires across MaxAttempts
	// never gets stuck and transitions to terminal "failed" state.
	crashLoop := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            "submission-dd33ee44ff55",
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/express@4.19.2"},
	}
	if err := store2.PutSubmission(ctx, crashLoop); err != nil {
		t.Fatal(err)
	}

	t0 := time.Now().UTC()
	for attempt := 1; attempt <= 2; attempt++ {
		c, ok, err := store2.ClaimNextSubmission(ctx, t0, 5*time.Millisecond, 2)
		if err != nil || !ok {
			t.Fatalf("attempt %d claim failed: ok=%v err=%v", attempt, ok, err)
		}
		if c.Attempts != attempt {
			t.Fatalf("got attempts=%d, want %d", c.Attempts, attempt)
		}
		t0 = t0.Add(10 * time.Millisecond) // advance past lease expiry
	}

	// Next claim after reaching maxAttempts=2 must fail closed and mark it "failed".
	if _, ok, err := store2.ClaimNextSubmission(ctx, t0, 5*time.Millisecond, 2); err != nil || ok {
		t.Fatalf("expected no runnable claim after exhausting maxAttempts, got ok=%v err=%v", ok, err)
	}
	failedSub, ok, err := store2.GetSubmission(ctx, crashLoop.ID)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if failedSub.Status != api.SubmissionFailed || failedSub.Error == "" {
		t.Fatalf("expected exhausted submission to transition to failed, got %+v", failedSub)
	}
}
