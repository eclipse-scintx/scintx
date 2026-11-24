// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// The worker trace test ties the Go WORKER code to the formal model.
//
// The lease vectors (lease_vectors_test.go) check that the stores follow
// the Lean model. But the proofs also rest on how a worker behaves:
//
//  1. Every write carries the attempt number of the worker's own claim.
//  2. After a refusal or a final write, the worker writes nothing more.
//  3. The worker's own lease deadline is never later than the stored lease.
//  4. A shutdown adds exactly one to Interruptions.
//  5. A retry delay never exceeds the limit.
//
// This test runs the real workers through many situations, with store calls
// that fail on purpose. It records every store call. Then the Lean model
// itself judges the recording (formal/LeaseProof/TraceCheck.lean): is each
// recorded run one that the model allows? If not, a worker broke one of the
// rules above, or the model no longer describes the worker.
//
// The judge is Lean, so the last step needs Lean (https://lean-lang.org/install/).
// Without it the scenarios still run (that is useful under the race
// detector), and then the test is skipped. ./scripts/formal.sh and CI set
// SCINTX_REQUIRE_LEAN=1, which turns a missing Lean into a failure, so the
// check cannot be skipped there.
func TestWorkerTracesFollowTheModel(t *testing.T) {
	var trace bytes.Buffer
	counts := make(map[string]int)
	for _, scenario := range traceScenarios() {
		runTraceScenario(t, scenario, &trace, counts)
	}
	// A recording that misses a kind of call would prove nothing about it.
	for _, kind := range []string{"claim", "exhaust", "renew", "complete", "fail", "delay", "interrupt", "release", "dropped", "refused", "lost answer"} {
		if counts[kind] == 0 {
			t.Errorf("the scenarios never produced %q; the recording is incomplete", kind)
		}
	}
	judgeTrace(t, findLake(t), trace.Bytes())
}

// runTraceScenario runs one scenario to the end and appends its recording.
func runTraceScenario(t *testing.T, scenario traceScenario, out io.Writer, counts map[string]int) {
	t.Helper()
	rng := rand.New(rand.NewSource(int64(len(scenario.name))))
	store := newTraceStore(func(call string) fault {
		if scenario.plan == nil {
			return deliver
		}
		return scenario.plan(rng, call)
	})
	timeout := scenario.timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	cfg := config.Default()
	cfg.Gateway.Workers = 2
	options := []orchestratorOption{
		withTestSettings(traceLease, timeout, scenario.hook),
		withRetryBackoff(traceBackoff),
		withPollInterval(5 * time.Millisecond),
	}
	first := newOrchestrator(cfg, store, options...)
	second := newOrchestrator(cfg, store, options...)

	var ids []string
	for n := 0; n < scenario.submissions; n++ {
		sub, err := first.Submit(context.Background(), api.ArtifactInput{PURL: fmt.Sprintf("pkg:npm/trace@1.0.%d", n)})
		if err != nil {
			t.Fatalf("%s: submit: %v", scenario.name, err)
		}
		ids = append(ids, sub.ID)
	}
	if scenario.restart {
		// Give the workers time to start, then shut one gateway down with
		// almost no grace period. Its running attempts are interrupted.
		time.Sleep(traceLease / 2)
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		first.ShutdownWithContext(ctx)
		cancel()
	}
	deadline := time.Now().Add(30 * time.Second)
	for _, id := range ids {
		for {
			sub, _, _ := store.inner.GetSubmission(context.Background(), id)
			if sub.Status.IsTerminal() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: submission %s is still %q", scenario.name, id, sub.Status)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	// Stop every worker before the recording is read.
	first.Shutdown()
	second.Shutdown()

	store.writeRuns(out, scenario.name, traceLease, DefaultMaxAttempts, traceBackoff<<maxBackoffDoublings)
	for kind, n := range store.counts {
		counts[kind] += n
	}
}

// findLake returns the path of Lean's build tool. It skips the test when
// Lean is not installed (or fails it, when SCINTX_REQUIRE_LEAN=1).
func findLake(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("lake"); err == nil {
		return path
	}
	// elan installs here. A shell opened before the install does not have
	// this folder on its PATH yet.
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"lake", "lake.exe"} {
			path := filepath.Join(home, ".elan", "bin", name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	if os.Getenv("SCINTX_REQUIRE_LEAN") == "1" {
		t.Fatal("lake not found, but SCINTX_REQUIRE_LEAN=1 says Lean must be installed")
	}
	t.Skip("the scenarios ran, but nothing judged them: lake not found; install Lean 4 (https://lean-lang.org/install/)")
	return ""
}

// judgeTrace lets the Lean model judge the recording.
func judgeTrace(t *testing.T, lake string, trace []byte) {
	t.Helper()
	formal, err := filepath.Abs(filepath.Join("..", "..", "formal"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "worker_traces.txt")
	if err := os.WriteFile(path, trace, 0o600); err != nil {
		t.Fatal(err)
	}
	// Build the judge first. This does nothing when it is already built.
	for _, args := range [][]string{
		{"build", "LeaseProof.TraceFile"},
		{"env", "lean", "--run", "JudgeTraces.lean", path},
	} {
		cmd := exec.Command(lake, args...)
		cmd.Dir = formal
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("lake %v: %v\nThe Lean model does not allow a recorded run:\n%s", args, err, out)
		}
		t.Logf("lake %s: %s", args[0], bytes.TrimSpace(out))
	}
}
