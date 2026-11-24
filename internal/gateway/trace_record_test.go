// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"
)

// This file holds how the recorder (trace_store_test.go) writes a store call
// down. It was split out to keep each file small.

// modelTime turns a real time into the model's time: nanoseconds since start.
func (s *traceStore) modelTime(at time.Time) int64 {
	return int64(at.Round(0).Sub(s.start))
}

// optional formats a time for the trace file. "-" means "none".
func (s *traceStore) optional(at time.Time, present bool) string {
	if !present || at.IsZero() {
		return "-"
	}
	return strconv.FormatInt(s.modelTime(at), 10)
}

// record writes one line. The fields are those of "Event" in
// formal/LeaseProof/TraceCheck.lean, in the same order.
func (s *traceStore) record(ctx context.Context, id, call string, k int, at time.Time, delay time.Duration, arrival, answer string) {
	t := int64(0)
	if !at.IsZero() {
		t = s.modelTime(at)
	}
	// The heartbeat gives each renewal a context that ends at its own lease
	// deadline. That is how the judge gets to see that deadline.
	deadline := "-"
	if call == "renew" {
		deadline = s.optional(ctx.Deadline())
	}
	s.inner.mu.RLock()
	entry := s.inner.submissions[id]
	s.inner.mu.RUnlock()
	line := fmt.Sprintf("ev %s %d %d %d %s %s %s %s %d %d %s", call, k, t, int64(delay), arrival, answer, deadline,
		entry.sub.Status, entry.sub.Attempts, entry.sub.Interruptions, s.optional(entry.leaseUntil, true))
	if _, seen := s.events[id]; !seen {
		s.ids = append(s.ids, id)
	}
	s.events[id] = append(s.events[id], line)
	s.counts[call]++
	s.counts[arrival]++
	if arrival == "accepted" && answer == "error" {
		s.counts["lost answer"]++
	}
}

// writeRuns writes the recording as one run per submission, in the format
// that formal/LeaseProof/TraceFile.lean reads.
func (s *traceStore) writeRuns(w io.Writer, label string, lease time.Duration, maxAttempts int, maxRetryDelay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, id := range s.ids {
		fmt.Fprintf(w, "run %s/%d %d %d %d\n", label, n, int64(lease), maxAttempts, int64(maxRetryDelay))
		for _, line := range s.events[id] {
			fmt.Fprintln(w, line)
		}
	}
}
