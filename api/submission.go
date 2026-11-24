// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import "time"

// SubmissionStatus represents the lifecycle state of a gateway submission.
type SubmissionStatus string

const (
	SubmissionAccepted  SubmissionStatus = "accepted"
	SubmissionRunning   SubmissionStatus = "running"
	SubmissionCompleted SubmissionStatus = "completed"
	SubmissionFailed    SubmissionStatus = "failed"
)

// Submission is the public resource returned by POST /v1/submissions and
// GET /v1/submissions/{id}.
type Submission struct {
	SchemaVersion string           `json:"schemaVersion"`
	ID            string           `json:"id"`
	Status        SubmissionStatus `json:"status"`
	AcceptedAt    time.Time        `json:"acceptedAt"`
	CompletedAt   *time.Time       `json:"completedAt,omitempty"`
	Artifact      ArtifactInput    `json:"artifact"`
	Error         string           `json:"error,omitempty"`
}

// ProblemDetails is an RFC 9457 / RFC 7807 error response body.
type ProblemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}
