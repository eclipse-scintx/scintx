// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds the situations that the worker trace test puts the real
// workers in (see trace_test.go). Each one makes the workers take a
// different path through execution.go, heartbeat.go and outcome.go.

const (
	// traceLease is short, so that leases run out within the test.
	traceLease = 60 * time.Millisecond
	// traceBackoff is the base retry delay. It doubles per attempt.
	traceBackoff = 3 * time.Millisecond
	// traceTimeout is the per-attempt limit in the scenarios that have one.
	traceTimeout = 200 * time.Millisecond
)

// traceScenario is one situation. Two gateways with two workers each share
// one store in every scenario.
type traceScenario struct {
	name        string
	submissions int
	// timeout is the per-attempt limit. Zero means "no limit in practice".
	timeout time.Duration
	// hook is the work of one attempt.
	hook hookFunc
	// plan picks the fault for each store call. Nil means "no faults".
	plan func(rng *rand.Rand, call string) fault
	// restart shuts the first gateway down in the middle of the work, as a
	// deploy does. The second gateway keeps running.
	restart bool
}

// traceScenarios lists every situation. Together they must make the workers
// use every store call (the test checks that).
func traceScenarios() []traceScenario {
	return []traceScenario{
		{name: "done", submissions: 3, hook: hookDone},
		{name: "retry-then-done", submissions: 3, hook: hookRetryUntilThirdAttempt},
		{name: "always-retry", submissions: 2, hook: hookRetry},
		{name: "broken", submissions: 2, hook: hookBroken},
		{name: "panic", submissions: 2, hook: hookPanic},
		// A long attempt: the heartbeat renews the lease many times.
		{name: "heartbeat", submissions: 2, hook: hookSlow},
		// The same with a store that answers slowly. This is the scenario
		// that catches a heartbeat that sets its deadline too late.
		{name: "slow-store", submissions: 2, hook: hookSlow, plan: planAlways("renew", slow)},
		// The answer of every "completed" write gets lost.
		{name: "lost-answer", submissions: 2, hook: hookDone, plan: planAlways("complete", lose)},
		// No renewal gets through. Every attempt loses its lease, until the
		// submission is out of attempts.
		{name: "lost-lease", submissions: 2, hook: hookBlock, plan: planAlways("renew", drop)},
		// A frozen worker: its renewal hangs until another worker has taken
		// the submission over and finished it. The late renewal is refused.
		{name: "frozen", submissions: 2, hook: hookBlockFirstAttempt, plan: planAlways("renew", stall)},
		{name: "timeout", submissions: 2, timeout: traceLease / 2, hook: hookBlock},
		{name: "restart", submissions: 6, timeout: traceTimeout, hook: hookBlockFirstAttempt, restart: true},
		{name: "restart-with-faults", submissions: 6, timeout: traceTimeout, hook: hookBlockFirstAttempt, plan: planShutdownFaults, restart: true},
		// Everything at once, with one call in five broken.
		{name: "chaos", submissions: 12, timeout: traceTimeout, hook: hookChaos(), plan: planChaos},
		{name: "chaos-restart", submissions: 12, timeout: traceTimeout, hook: hookChaos(), plan: planChaos, restart: true},
	}
}

func hookDone(context.Context, api.Submission) error { return nil }

func hookRetry(context.Context, api.Submission) error {
	return fmt.Errorf("%w: provider is busy", ErrRetryable)
}

func hookRetryUntilThirdAttempt(ctx context.Context, sub api.Submission) error {
	if sub.Attempts < 3 {
		return hookRetry(ctx, sub)
	}
	return nil
}

func hookBroken(context.Context, api.Submission) error { return errors.New("provider is broken") }

func hookPanic(context.Context, api.Submission) error { panic("provider adapter panicked") }

// hookSlow works for four lease durations. Only the heartbeat keeps the
// lease alive that long.
func hookSlow(ctx context.Context, _ api.Submission) error {
	select {
	case <-time.After(4 * traceLease):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// hookBlock never finishes by itself. It ends when the attempt is canceled:
// by a lost lease, a timeout, or a shutdown.
func hookBlock(ctx context.Context, _ api.Submission) error {
	<-ctx.Done()
	return ctx.Err()
}

func hookBlockFirstAttempt(ctx context.Context, sub api.Submission) error {
	if sub.Attempts == 1 {
		return hookBlock(ctx, sub)
	}
	return nil
}

// hookChaos picks one of the hooks above at random for every attempt.
func hookChaos() hookFunc {
	var mu sync.Mutex
	rng := rand.New(rand.NewSource(7))
	hooks := []hookFunc{hookDone, hookDone, hookRetry, hookBroken, hookPanic, hookSlow, hookBlock}
	return func(ctx context.Context, sub api.Submission) error {
		mu.Lock()
		hook := hooks[rng.Intn(len(hooks))]
		mu.Unlock()
		return hook(ctx, sub)
	}
}

// planAlways breaks every call of one kind in the same way.
func planAlways(kind string, how fault) func(*rand.Rand, string) fault {
	return func(_ *rand.Rand, call string) fault {
		if call == kind {
			return how
		}
		return deliver
	}
}

// planShutdownFaults breaks two of three shutdown writes.
func planShutdownFaults(rng *rand.Rand, call string) fault {
	if call != "interrupt" && call != "release" {
		return deliver
	}
	return []fault{deliver, drop, lose}[rng.Intn(3)]
}

// planChaos drops one call in ten, and loses the answer of one more in ten.
func planChaos(rng *rand.Rand, _ string) fault {
	switch rng.Intn(10) {
	case 0:
		return drop
	case 1:
		return lose
	}
	return deliver
}
