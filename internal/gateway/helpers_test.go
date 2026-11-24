// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// hookFunc is the signature of the test-only execution hook.
type hookFunc = func(ctx context.Context, sub api.Submission) error

// succeedingHook is a hook for a provider that always finishes its work.
// Tests that only need a submission to reach "completed" install it. With
// no hook at all, a submission fails closed (see ErrNoExecutor).
func succeedingHook(context.Context, api.Submission) error { return nil }

// withTestSettings returns an option that fixes the lease duration, the
// per-attempt timeout, and the execution hook before any worker starts.
// A zero duration keeps the default value.
//
// Tests must use this instead of assigning orch.leaseDuration or
// orch.execHook after construction. The workers are already running by then,
// so a late assignment is a data race (go test -race fails on it).
func withTestSettings(lease, maxExec time.Duration, hook hookFunc) orchestratorOption {
	return func(o *Orchestrator) {
		if lease > 0 {
			o.leaseDuration = lease
		}
		if maxExec > 0 {
			o.maxExecutionDuration = maxExec
		}
		o.execHook = hook
	}
}

// withRetryBackoff returns an option that sets the base retry delay. Tests
// use a few milliseconds so they do not wait out the 5 second default.
func withRetryBackoff(d time.Duration) orchestratorOption {
	return func(o *Orchestrator) { o.retryBackoff = d }
}

// waitForStatus polls the store until the submission reaches want, and fails
// the test after five seconds. orch.Wait cannot be used for this when a
// retry backoff is involved: a submission that is waiting out its backoff is
// not claimable, so Wait returns before the retry runs.
func waitForStatus(t *testing.T, store Store, id string, want api.SubmissionStatus) api.Submission {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _, err := store.GetSubmission(context.Background(), id)
		if err == nil && got.Status == want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("submission %s did not reach %q in time: last=%+v err=%v", id, want, got, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
