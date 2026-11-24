// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// These tests cover how one execution attempt ends: interrupted by a
// shutdown, retried after a backoff, or saved as completed.

// TestGracefulShutdownsDoNotConsumeAttempts restarts the gateway four times
// in the middle of a long scan. Before the fix, the third restart used up the
// last attempt and the scan failed with "exceeded maximum execution attempts".
func TestGracefulShutdownsDoNotConsumeAttempts(t *testing.T) {
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "deploys.db"))
	ctx := context.Background()
	cfg := config.Default()
	cfg.Gateway.Workers = 1
	var id string

	for restart := 1; restart <= 4; restart++ {
		store, err := OpenStore(dsn)
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		var once sync.Once
		hook := func(execCtx context.Context, _ api.Submission) error {
			once.Do(func() { close(started) })
			<-execCtx.Done() // A long scan that never finishes before the deploy.
			return execCtx.Err()
		}
		orch := newOrchestrator(cfg, store, withTestSettings(0, 0, hook))
		if restart == 1 {
			sub, err := orch.Submit(ctx, api.ArtifactInput{PURL: "pkg:npm/long-scan@1.0.0"})
			if err != nil {
				t.Fatal(err)
			}
			id = sub.ID
		}
		<-started
		shutCtx, cancel := context.WithTimeout(ctx, time.Millisecond)
		orch.ShutdownWithContext(shutCtx)
		cancel()

		got, _, _ := store.GetSubmission(ctx, id)
		if got.Status != api.SubmissionRunning || got.Attempts != restart || got.Interruptions != restart {
			t.Fatalf("after shutdown %d: expected running with attempts=interruptions=%d, got %+v", restart, restart, got)
		}
		_ = store.Close()
	}

	// The fifth start has no deploy in the way, so the scan can finish.
	store, err := OpenStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	orch := newOrchestrator(cfg, store, withTestSettings(0, 0, succeedingHook))
	defer orch.Shutdown()
	got := waitForStatus(t, store, id, api.SubmissionCompleted)
	if got.Attempts != 5 || got.Interruptions != 4 {
		t.Fatalf("expected attempts=5 interruptions=4, got %+v", got)
	}
}

// TestRetryableErrorWaitsForBackoff checks that retries are spaced out and
// that the stored error does not expose the hook's own error text.
func TestRetryableErrorWaitsForBackoff(t *testing.T) {
	const backoff = 40 * time.Millisecond
	store := NewMemoryStore()
	var mu sync.Mutex
	var calls []time.Time
	hook := func(context.Context, api.Submission) error {
		mu.Lock()
		calls = append(calls, time.Now())
		mu.Unlock()
		return errors.Join(ErrRetryable, errors.New("HTTP 429 from https://provider.internal/api?token=secret"))
	}
	orch := newOrchestrator(config.Default(), store, withTestSettings(0, 0, hook), withRetryBackoff(backoff))
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/rate-limited@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	got := waitForStatus(t, store, sub.ID, api.SubmissionFailed)

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 || got.Attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d calls and attempts=%d", len(calls), got.Attempts)
	}
	// The delay doubles: one backoff before attempt 2, two before attempt 3.
	if gap := calls[1].Sub(calls[0]); gap < backoff {
		t.Fatalf("attempt 2 ran after %s, want at least %s", gap, backoff)
	}
	if gap := calls[2].Sub(calls[1]); gap < 2*backoff {
		t.Fatalf("attempt 3 ran after %s, want at least %s", gap, 2*backoff)
	}
	// The public error must be the fixed reason. No sentinel text, no newline,
	// and nothing from the upstream error.
	if got.Error != publicFailureReason || strings.ContainsAny(got.Error, "\n") || strings.Contains(got.Error, "secret") {
		t.Fatalf("unexpected public error %q", got.Error)
	}
}

// flakySaveStore fails the first attempt to save a "completed" state.
type flakySaveStore struct {
	Store
	failed atomic.Bool
}

func (f *flakySaveStore) PutSubmission(ctx context.Context, sub api.Submission) error {
	if sub.Status == api.SubmissionCompleted && f.failed.CompareAndSwap(false, true) {
		return errors.New("simulated brief database error")
	}
	return f.Store.PutSubmission(ctx, sub)
}

// TestBriefSaveErrorDoesNotFailASuccessfulRun checks that a run which
// succeeded is not marked "failed" just because one save went wrong.
func TestBriefSaveErrorDoesNotFailASuccessfulRun(t *testing.T) {
	store := &flakySaveStore{Store: NewMemoryStore()}
	hook := func(context.Context, api.Submission) error { return nil }
	// A 50ms lease lets the second attempt start soon after the failed save.
	orch := newOrchestrator(config.Default(), store, withTestSettings(50*time.Millisecond, 0, hook))
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/saved-late@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if got.Attempts != 2 || got.Error != "" {
		t.Fatalf("expected completed on attempt 2 with no error, got %+v", got)
	}
}

// TestSuccessAtTheDeadlineIsCompleted checks that a hook which returns nil
// is recorded as completed even if the time limit passed while it finished.
func TestSuccessAtTheDeadlineIsCompleted(t *testing.T) {
	store := NewMemoryStore()
	hook := func(execCtx context.Context, _ api.Submission) error {
		<-execCtx.Done() // The limit has now passed...
		return nil       // ...but the work did finish.
	}
	orch := newOrchestrator(config.Default(), store, withTestSettings(5*time.Second, 20*time.Millisecond, hook))
	defer orch.Shutdown()

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/photo-finish@1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if got.Attempts != 1 {
		t.Fatalf("expected completed on attempt 1, got %+v", got)
	}
}
