// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// These tests cover the poll timer (pollLoop in worker.go).
//
// Before, every worker had its own 100 millisecond ticker. An idle gateway
// then ran (workers x 10) empty claim transactions per second. Now there is
// one timer for the whole gateway. The tests check three things:
//
//  1. An idle gateway claims at most once per tick.
//  2. Work that turns up without a wake signal is still found.
//  3. One wake is enough to start several workers.

// countingStore counts the claim calls that have returned.
type countingStore struct {
	Store
	claims atomic.Int64
}

// ClaimNextSubmission counts the call AFTER the real store has answered. So
// when the counter shows a number, that many claims are completely over.
func (s *countingStore) ClaimNextSubmission(ctx context.Context, now time.Time, d time.Duration, maxAttempts int) (api.Submission, bool, error) {
	defer s.claims.Add(1)
	return s.Store.ClaimNextSubmission(ctx, now, d, maxAttempts)
}

// pollTestWorkers is the pool size in these tests. It is well above one, so
// "once per worker" and "once per gateway" give very different counts.
const pollTestWorkers = 8

// startupClaims is the number of claims a new gateway makes before it goes
// idle: each worker looks for work once, and newOrchestrator sends one wake.
const startupClaims = pollTestWorkers + 1

// newPollTestGateway starts a gateway with pollTestWorkers workers on a
// counting store. It waits until the startup claims are over, so the workers
// are idle when it returns.
func newPollTestGateway(t *testing.T, poll time.Duration, hook hookFunc) (*Orchestrator, *countingStore) {
	t.Helper()
	store := &countingStore{Store: NewMemoryStore()}
	cfg := config.Default()
	cfg.Gateway.Workers = pollTestWorkers
	orch := newOrchestrator(cfg, store, withTestSettings(0, 0, hook), withPollInterval(poll))
	t.Cleanup(orch.Shutdown)
	deadline := time.Now().Add(5 * time.Second)
	for store.claims.Load() < startupClaims {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d startup claims happened", store.claims.Load(), startupClaims)
		}
		time.Sleep(time.Millisecond)
	}
	return orch, store
}

// putUnsignalled stores a new submission directly, without Submit. So no
// worker is woken. This is what a submission from another gateway, or a
// retry whose backoff ran out, looks like to this gateway.
func putUnsignalled(t *testing.T, store Store, n int) string {
	t.Helper()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		Status:        api.SubmissionAccepted,
		AcceptedAt:    time.Now(),
		Artifact:      api.ArtifactInput{PURL: fmt.Sprintf("pkg:npm/poll@1.0.%d", n)},
	}
	if err := store.PutSubmission(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	return sub.ID
}

func TestIdleGatewayClaimsAtMostOncePerTick(t *testing.T) {
	const poll = 20 * time.Millisecond
	start := time.Now()
	_, store := newPollTestGateway(t, poll, succeedingHook)
	time.Sleep(20 * poll)

	// Read the counter first and the clock second. Then every counted claim
	// happened within "elapsed", and the limit below can never be too low.
	got := store.claims.Load()
	elapsed := time.Since(start)
	ticks := int64(elapsed / poll)
	// One claim per tick, plus the startup claims. The old code made one
	// claim per tick PER WORKER, which is about eight times this limit.
	if limit := startupClaims + ticks; got > limit {
		t.Fatalf("idle gateway made %d claims in %v; want at most %d (one per %v tick)", got, elapsed, limit, poll)
	}
	// The timer must still run. Without it, expired leases are never found.
	if got <= startupClaims {
		t.Fatalf("idle gateway made %d claims in %v; the poll timer never fired", got, elapsed)
	}
}

func TestPollFindsWorkThatWasNotSignalled(t *testing.T) {
	_, store := newPollTestGateway(t, 10*time.Millisecond, succeedingHook)
	id := putUnsignalled(t, store, 0)
	// No worker was woken for this submission. Only the poll can find it.
	waitForStatus(t, store, id, api.SubmissionCompleted)
}

func TestOneWakeStartsEveryNeededWorker(t *testing.T) {
	const jobs = 3
	var running atomic.Int32
	release := make(chan struct{})
	hook := func(ctx context.Context, _ api.Submission) error {
		running.Add(1)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// An hour means the poll timer never fires in this test. The single
	// signalWake call below stands in for exactly one tick.
	orch, store := newPollTestGateway(t, time.Hour, hook)
	// Registered after the gateway, so it runs BEFORE the shutdown and the
	// blocked hooks can finish.
	t.Cleanup(func() { close(release) })

	for n := 0; n < jobs; n++ {
		putUnsignalled(t, store, n)
	}
	orch.signalWake()

	// The first worker claims a job and wakes the second, and so on. So all
	// three jobs must be running at the same time, after one wake.
	deadline := time.Now().Add(5 * time.Second)
	for running.Load() < jobs {
		if time.Now().After(deadline) {
			t.Fatalf("one wake started %d of %d jobs; a claim must wake the next worker", running.Load(), jobs)
		}
		time.Sleep(time.Millisecond)
	}
}
