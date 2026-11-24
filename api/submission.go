// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"fmt"
	"time"
)

// SubmissionStatus represents the explicit lifecycle state of a gateway submission.
//
// Valid state transitions:
//
//	(new)     -> accepted
//	accepted  -> running | failed
//	running   -> running (re-claimed after lease expiry/restart) | completed | failed
//	completed -> (terminal)
//	failed    -> (terminal)
type SubmissionStatus string

const (
	SubmissionAccepted  SubmissionStatus = "accepted"
	SubmissionRunning   SubmissionStatus = "running"
	SubmissionCompleted SubmissionStatus = "completed"
	SubmissionFailed    SubmissionStatus = "failed"
)

// IsValid reports whether s is a known SubmissionStatus value.
func (s SubmissionStatus) IsValid() bool {
	switch s {
	case SubmissionAccepted, SubmissionRunning, SubmissionCompleted, SubmissionFailed:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether s is a terminal submission state (completed or failed).
func (s SubmissionStatus) IsTerminal() bool {
	return s == SubmissionCompleted || s == SubmissionFailed
}

// CanTransition reports whether a transition from current to next is permitted
// by the submission state machine. Unknown states or transitions out of
// terminal states are rejected (fail-closed).
//
// Note that running -> running is permitted so an in-flight submission whose
// lease expired across a gateway restart can be re-claimed and completed.
func CanTransition(current, next SubmissionStatus) bool {
	if !next.IsValid() {
		return false
	}
	switch current {
	case "":
		return next == SubmissionAccepted
	case SubmissionAccepted:
		return next == SubmissionRunning || next == SubmissionFailed
	case SubmissionRunning:
		return next == SubmissionRunning || next == SubmissionCompleted || next == SubmissionFailed
	case SubmissionCompleted, SubmissionFailed:
		return false
	default:
		return false
	}
}

// Submission is the public resource returned by POST /v1/submissions and
// GET /v1/submissions/{id}.
type Submission struct {
	SchemaVersion string           `json:"schemaVersion"`
	ID            string           `json:"id"`
	Status        SubmissionStatus `json:"status"`
	Attempts      int              `json:"attempts,omitempty"`
	// Interruptions counts attempts that a graceful gateway shutdown cut
	// short. Those attempts were not the submission's fault, so they do not
	// count toward the attempt cap (see AttemptsExhausted).
	Interruptions int           `json:"interruptions,omitempty"`
	AcceptedAt    time.Time     `json:"acceptedAt"`
	CompletedAt   *time.Time    `json:"completedAt,omitempty"`
	Artifact      ArtifactInput `json:"artifact"`
	Error         string        `json:"error,omitempty"`
}

// AttemptsExhausted reports whether the submission has used up its attempt
// budget of maxAttempts.
//
// Attempts is also the fencing token, so it must only ever go up. That is why
// a shutdown does not hand an attempt back by lowering Attempts. Instead the
// shutdown adds one to Interruptions, and the budget check subtracts it here.
// Before this, three deploys during one long scan failed the scan for good.
func (s Submission) AttemptsExhausted(maxAttempts int) bool {
	return s.Attempts-s.Interruptions >= maxAttempts
}

// TransitionTo validates and applies a state transition on the Submission.
// It fails closed if the transition is invalid or if a failed transition omits
// an error reason.
func (s *Submission) TransitionTo(next SubmissionStatus, errMsg string, at time.Time) error {
	if !CanTransition(s.Status, next) {
		return fmt.Errorf("invalid submission state transition from %q to %q", s.Status, next)
	}
	if next == SubmissionFailed && errMsg == "" {
		return fmt.Errorf("failed submission transition requires a non-empty error reason")
	}
	s.Status = next
	if next.IsTerminal() {
		ts := at.UTC()
		s.CompletedAt = &ts
		if next == SubmissionFailed {
			s.Error = errMsg
		}
	}
	return nil
}

// ProblemDetails is an RFC 9457 / RFC 7807 error response body.
type ProblemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}
