// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"time"

	"github.com/yeeth-security/scintx/api"
)

// hookFunc is the signature of the test-only execution hook.
type hookFunc = func(ctx context.Context, sub api.Submission) error

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
