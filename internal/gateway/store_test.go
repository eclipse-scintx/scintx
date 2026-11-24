// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
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

	store1, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore(1) failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	inFlight := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	}
	if err := store1.PutSubmission(ctx, inFlight); err != nil {
		t.Fatalf("PutSubmission(inFlight) failed: %v", err)
	}

	// Duplicate creation with the same ID must fail closed instead of overwriting.
	if err := store1.PutSubmission(ctx, inFlight); err == nil {
		t.Fatal("expected duplicate submission ID creation to fail closed")
	}

	// Simulate worker claiming the submission with a short 10ms lease, then crashing.
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
	if err := store1.Close(); err != nil {
		t.Fatalf("Close(1) failed: %v", err)
	}

	// Wait for the 10ms lease to expire, start a new gateway Orchestrator on store2,
	// and verify it automatically picks the in-flight submission back up and completes it.
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
	if recovered.Status != api.SubmissionCompleted || recovered.Attempts != 2 {
		t.Fatalf("expected completed with attempts=2, got %+v", recovered)
	}
}

func TestLeaseHeartbeatAndAttemptFencing(t *testing.T) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "fence.db"))
	store, err := OpenStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	}
	if err := store.PutSubmission(ctx, sub); err != nil {
		t.Fatal(err)
	}

	worker1Claim, ok, err := store.ClaimNextSubmission(ctx, now, 5*time.Millisecond, 3)
	if err != nil || !ok || worker1Claim.Attempts != 1 {
		t.Fatalf("worker1 claim failed: ok=%v err=%v", ok, err)
	}

	// Lease expires; Worker 2 claims the submission (attempts becomes 2).
	worker2Claim, ok, err := store.ClaimNextSubmission(ctx, now.Add(10*time.Millisecond), 30*time.Second, 3)
	if err != nil || !ok || worker2Claim.Attempts != 2 {
		t.Fatalf("worker2 claim failed: ok=%v err=%v", ok, err)
	}

	// Stale Worker 1 tries to renew lease or save completed result with attempt=1 -> fenced!
	if err := store.RenewLease(ctx, sub.ID, 1, now.Add(12*time.Millisecond), 30*time.Second); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("expected ErrStaleAttempt on stale RenewLease, got %v", err)
	}
	_ = worker1Claim.TransitionTo(api.SubmissionCompleted, "", now.Add(15*time.Millisecond))
	if err := store.PutSubmission(ctx, worker1Claim); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("expected ErrStaleAttempt on stale PutSubmission, got %v", err)
	}

	// Worker 2 (attempt=2) succeeds.
	if err := worker2Claim.TransitionTo(api.SubmissionCompleted, "", now.Add(20*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSubmission(ctx, worker2Claim); err != nil {
		t.Fatalf("expected current worker2 PutSubmission to succeed, got %v", err)
	}

	// Verify heartbeat renewal keeps a slow execution alive past initial lease duration.
	orch := NewOrchestrator(config.Default(), store)
	defer orch.Shutdown()
	orch.leaseDuration = 15 * time.Millisecond
	orch.execHook = func(execCtx context.Context, _ api.Submission) error {
		select {
		case <-time.After(45 * time.Millisecond):
			return nil
		case <-execCtx.Done():
			return execCtx.Err()
		}
	}

	slowSub, err := orch.Submit(ctx, api.ArtifactInput{PURL: "pkg:npm/react@18.3.1"})
	if err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	finalSlow, ok, err := store.GetSubmission(ctx, slowSub.ID)
	if err != nil || !ok || finalSlow.Status != api.SubmissionCompleted || finalSlow.Attempts != 1 {
		t.Fatalf("expected slow submission to complete on attempt 1 via heartbeat, got %+v", finalSlow)
	}
}

func TestConcurrentLongAndShortTasksAndRetryableError(t *testing.T) {
	store := NewMemoryStore()
	cfg := config.Default()
	cfg.Gateway.Workers = 4
	orch := NewOrchestrator(cfg, store)
	defer orch.Shutdown()

	longStarted := make(chan struct{})
	fastDone := make(chan struct{})
	orch.execHook = func(execCtx context.Context, sub api.Submission) error {
		if sub.Artifact.PURL == "pkg:generic/long-binary-scan@1.0.0" {
			close(longStarted)
			<-fastDone
			return nil
		}
		if sub.Attempts == 1 {
			return errors.Join(ErrRetryable, errors.New("HTTP 503 service unavailable"))
		}
		close(fastDone)
		return nil
	}

	longSub, _ := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:generic/long-binary-scan@1.0.0"})
	<-longStarted
	fastSub, _ := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/transient-http@1.0.0"})
	orch.Wait()

	gotLong, _, _ := store.GetSubmission(context.Background(), longSub.ID)
	gotFast, _, _ := store.GetSubmission(context.Background(), fastSub.ID)
	if gotLong.Status != api.SubmissionCompleted || gotFast.Status != api.SubmissionCompleted || gotFast.Attempts != 2 {
		t.Fatalf("expected concurrent completion and retry (attempts=2), got long=%+v fast=%+v", gotLong, gotFast)
	}
}
