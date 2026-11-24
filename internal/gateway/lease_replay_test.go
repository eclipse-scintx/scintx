// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// This file replays one lease scenario against a store. It was split out of
// lease_vectors_test.go to keep each file small.

// leaseReplay replays one scenario on one new submission.
type leaseReplay struct {
	t           *testing.T
	store       Store
	id          string
	start       time.Time // The real time that stands for model time 0.
	lease       time.Duration
	maxAttempts int
	exactClock  bool
}

// leaseRow is the part of a stored row that the model talks about. lease is
// the lease_until text, and "" means "no lease".
type leaseRow struct {
	status        string
	attempts      int
	interruptions int
	lease         string
}

// at turns a model time into a real time.
func (r *leaseReplay) at(modelTime int) time.Time {
	return r.start.Add(time.Duration(modelTime) * leaseVectorTick)
}

// run creates the submission, makes every call, and compares after each one.
func (r *leaseReplay) run(scenario int, s leaseScenario) {
	r.t.Helper()
	sub := api.Submission{SchemaVersion: api.SchemaVersionV1, ID: r.id, Status: api.SubmissionAccepted, AcceptedAt: r.start, Artifact: api.ArtifactInput{PURL: "pkg:npm/vector@1.0.0"}}
	if err := r.store.PutSubmission(context.Background(), sub); err != nil {
		r.t.Fatalf("scenario %d: create the submission: %v", scenario, err)
	}
	for n, step := range s.Steps {
		accepted := r.apply(step)
		got, want := r.row(), leaseRow{status: step.Status, attempts: step.Attempts, interruptions: step.Interruptions}
		if step.Lease != nil {
			want.lease = formatTimestampUTC(r.at(*step.Lease))
		}
		if !r.exactClock {
			// PostgreSQL writes the lease with its own clock, so the exact
			// text cannot be predicted. Only compare whether there is one.
			got.lease, want.lease = presence(got.lease), presence(want.lease)
		}
		if accepted != step.OK || got != want {
			r.t.Fatalf("scenario %d, step %d (%s with k=%d t=%d d=%d i=%d):\n the model says accepted=%v row=%+v\n the store gave accepted=%v row=%+v",
				scenario, n, step.Op, step.K, step.T, step.D, step.I, step.OK, want, accepted, got)
		}
	}
}

// presence reduces a lease to "there is one" or "there is none".
func presence(lease string) string {
	if lease == "" {
		return ""
	}
	return "set"
}

// apply makes one store call and reports whether the store accepted it.
func (r *leaseReplay) apply(step leaseStep) bool {
	r.t.Helper()
	ctx := context.Background()
	switch step.Op {
	case "claim":
		sub, ok, err := r.store.ClaimNextSubmission(ctx, r.at(step.T), r.lease, r.maxAttempts)
		if err != nil {
			r.t.Fatalf("ClaimNextSubmission: %v", err)
		}
		if ok && (sub.ID != r.id || sub.Attempts != step.Attempts) {
			r.t.Fatalf("the claim returned %s at attempt %d, want %s at attempt %d", sub.ID, sub.Attempts, r.id, step.Attempts)
		}
		return ok
	case "renew":
		return r.fenced(r.store.RenewLease(ctx, r.id, step.K, r.at(step.T), r.lease))
	case "delayRetry":
		return r.fenced(r.store.DelayRetry(ctx, r.id, step.K, r.at(step.T), time.Duration(step.D)*leaseVectorTick))
	case "release":
		return r.fenced(r.store.ReleaseLease(ctx, r.id, step.K))
	case "complete", "fail", "interrupt":
		return r.put(ctx, step)
	}
	r.t.Fatalf("unknown call %q in the lease vectors", step.Op)
	return false
}

// fenced turns the answer of a lease call into "accepted or not". The only
// refusal such a call may give is ErrStaleAttempt.
func (r *leaseReplay) fenced(err error) bool {
	r.t.Helper()
	if err != nil && !errors.Is(err, ErrStaleAttempt) {
		r.t.Fatalf("a lease call failed with something other than ErrStaleAttempt: %v", err)
	}
	return err == nil
}

// put sends the write a worker would send: the submission as stored, but
// with the worker's own attempt number (step.K), which may be out of date.
func (r *leaseReplay) put(ctx context.Context, step leaseStep) bool {
	r.t.Helper()
	sub, ok, err := r.store.GetSubmission(ctx, r.id)
	if err != nil || !ok {
		r.t.Fatalf("GetSubmission: ok=%v err=%v", ok, err)
	}
	sub.Attempts = step.K
	finished := r.start.UTC()
	switch step.Op {
	case "complete":
		sub.Status, sub.CompletedAt = api.SubmissionCompleted, &finished
	case "fail":
		sub.Status, sub.CompletedAt, sub.Error = api.SubmissionFailed, &finished, "replayed failure"
	default: // "interrupt": a running -> running write with a new count.
		sub.Status, sub.Interruptions = api.SubmissionRunning, step.I
	}
	return r.store.PutSubmission(ctx, sub) == nil
}

// row reads the stored row directly, below the Store interface. The
// interface does not show the lease, and for SQL the status and attempts
// columns must be compared too, not only the JSON payload.
func (r *leaseReplay) row() leaseRow {
	r.t.Helper()
	switch store := r.store.(type) {
	case *MemoryStore:
		store.mu.RLock()
		defer store.mu.RUnlock()
		entry := store.submissions[r.id]
		row := leaseRow{status: string(entry.sub.Status), attempts: entry.sub.Attempts, interruptions: entry.sub.Interruptions}
		if !entry.leaseUntil.IsZero() {
			row.lease = formatTimestampUTC(entry.leaseUntil)
		}
		return row
	case *SQLStore:
		query := `SELECT status, attempts, lease_until, payload_json FROM submissions WHERE id = ?`
		if store.postgres {
			query = `SELECT status, attempts, lease_until, payload_json FROM submissions WHERE id = $1`
		}
		var row leaseRow
		var payload string
		if err := store.db.QueryRow(query, r.id).Scan(&row.status, &row.attempts, &row.lease, &payload); err != nil {
			r.t.Fatalf("read the row: %v", err)
		}
		var sub api.Submission
		if err := json.Unmarshal([]byte(payload), &sub); err != nil {
			r.t.Fatalf("parse the payload: %v", err)
		}
		// The columns drive the claim query. The payload is what the API
		// returns. They must never disagree.
		if string(sub.Status) != row.status || sub.Attempts != row.attempts {
			r.t.Fatalf("columns (%s, attempt %d) and payload (%s, attempt %d) disagree", row.status, row.attempts, sub.Status, sub.Attempts)
		}
		row.interruptions = sub.Interruptions
		return row
	}
	r.t.Fatalf("no way to read a row of %T", r.store)
	return leaseRow{}
}
