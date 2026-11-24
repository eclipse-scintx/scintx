// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
)

func TestOrchestratorSubmitAndStatus(t *testing.T) {
	cfg := config.Default()
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "test.db"))
	store, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	orch := NewOrchestrator(cfg, store)
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{
		PURL: "pkg:npm/lodash@4.17.20",
	})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	orch.Wait()

	finalSub, ok, err := store.GetSubmission(context.Background(), sub.ID)
	if err != nil {
		t.Fatalf("GetSubmission failed: %v", err)
	}
	if !ok {
		t.Fatal("expected submission in store")
	}
	if finalSub.Status != api.SubmissionCompleted {
		t.Fatalf("expected status completed, got %q", finalSub.Status)
	}
	if finalSub.CompletedAt == nil {
		t.Fatal("expected completedAt timestamp")
	}
	if finalSub.Attempts != 1 {
		t.Fatalf("expected attempts=1, got %d", finalSub.Attempts)
	}
}

func TestMaxExecutionDurationTimeout(t *testing.T) {
	store := NewMemoryStore()
	orch := NewOrchestrator(config.Default(), store)
	defer orch.Shutdown()
	orch.leaseDuration = 10 * time.Millisecond
	orch.maxExecutionDuration = 25 * time.Millisecond

	// Simulate a hung execution that waits until execCtx is canceled by maxExecutionDuration.
	orch.execHook = func(execCtx context.Context, _ api.Submission) error {
		<-execCtx.Done()
		return execCtx.Err()
	}

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	got, ok, err := store.GetSubmission(context.Background(), sub.ID)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if got.Status != api.SubmissionFailed || !strings.Contains(got.Error, "timed out") {
		t.Fatalf("expected failed timeout status, got status=%q error=%q", got.Status, got.Error)
	}
}

type partitionStore struct {
	Store
	failRenew atomic.Bool
}

func (p *partitionStore) RenewLease(ctx context.Context, id string, attempt int, now time.Time, d time.Duration) error {
	if p.failRenew.Load() {
		return errors.New("simulated database network partition")
	}
	return p.Store.RenewLease(ctx, id, attempt, now, d)
}

func TestHeartbeatLocalLeaseExpiryOnDBPartition(t *testing.T) {
	ps := &partitionStore{Store: NewMemoryStore()}
	ps.failRenew.Store(true)

	orch := NewOrchestrator(config.Default(), ps)
	defer orch.Shutdown()
	orch.leaseDuration = 12 * time.Millisecond
	orch.maxExecutionDuration = 5 * time.Second

	var canceledByLeaseLoss atomic.Bool
	orch.execHook = func(execCtx context.Context, sub api.Submission) error {
		if sub.Attempts == 1 {
			// Attempt 1 experiences a DB partition: wait for local leaseDeadline to cancel execCtx.
			<-execCtx.Done()
			canceledByLeaseLoss.Store(true)
			// Heal the partition after Attempt 1 aborts so Attempt 2 can succeed.
			ps.failRenew.Store(false)
			return execCtx.Err()
		}
		return nil
	}

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	if !canceledByLeaseLoss.Load() {
		t.Fatal("expected worker to cancel execCtx when local leaseDeadline expired during DB partition")
	}
	got, _, _ := ps.GetSubmission(context.Background(), sub.ID)
	if got.Status != api.SubmissionCompleted || got.Attempts != 2 {
		t.Fatalf("expected attempt 1 to abort on lease loss and attempt 2 to complete, got status=%q attempts=%d", got.Status, got.Attempts)
	}
}

func TestShutdownReleasesActiveLeaseImmediately(t *testing.T) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "shutdown.db"))
	store, err := OpenStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	orch := NewOrchestrator(config.Default(), store)
	orch.leaseDuration = 30 * time.Second

	started := make(chan struct{})
	orch.execHook = func(execCtx context.Context, _ api.Submission) error {
		close(started)
		<-execCtx.Done()
		return execCtx.Err()
	}

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatal(err)
	}
	<-started

	// Trigger shutdown with an already-expired context so the active worker is interrupted.
	shutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	orch.ShutdownWithContext(shutCtx)

	// Because ReleaseLease cleared lease_until, another worker can claim it immediately (0ms wait)
	// even though the original leaseDuration was 30s.
	reclaimed, ok, err := store.ClaimNextSubmission(context.Background(), time.Now().UTC(), 30*time.Second, 3)
	if err != nil || !ok || reclaimed.ID != sub.ID || reclaimed.Attempts != 2 {
		t.Fatalf("expected immediate re-claim after shutdown lease release, got ok=%v sub=%+v err=%v", ok, reclaimed, err)
	}
}

func TestFixedWidthNanosecondOrdering(t *testing.T) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "order.db"))
	store, err := OpenStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	// t1 ends in .500000000Z (RFC3339Nano formats as ".5Z"); t2 is 1ns later (".500000001Z").
	t1 := time.Date(2026, 11, 24, 0, 0, 0, 500_000_000, time.UTC)
	t2 := time.Date(2026, 11, 24, 0, 0, 0, 500_000_001, time.UTC)

	sub1 := api.Submission{SchemaVersion: "1", ID: api.NewID("submission"), Status: api.SubmissionAccepted, AcceptedAt: t1, Artifact: api.ArtifactInput{PURL: "pkg:npm/a@1.0.0"}}
	sub2 := api.Submission{SchemaVersion: "1", ID: api.NewID("submission"), Status: api.SubmissionAccepted, AcceptedAt: t2, Artifact: api.ArtifactInput{PURL: "pkg:npm/b@1.0.0"}}

	if err := store.PutSubmission(ctx, sub2); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSubmission(ctx, sub1); err != nil {
		t.Fatal(err)
	}

	first, ok, err := store.ClaimNextSubmission(ctx, t2, time.Minute, 3)
	if err != nil || !ok || first.ID != sub1.ID {
		t.Fatalf("expected sub1 (earlier by 1ns) to be claimed first, got %s (want %s)", first.ID, sub1.ID)
	}
}
