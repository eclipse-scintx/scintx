// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import "time"

// SubmissionStatus represents the lifecycle state of a submission (#67, #69, #75).
// Open VSX polls $.status and maps accepted -> SUBMITTED, running -> PROCESSING,
// completed -> COMPLETED, and failed -> FAILED (#67).
type SubmissionStatus string

const (
	SubmissionAccepted  SubmissionStatus = "accepted"
	SubmissionRunning   SubmissionStatus = "running"
	SubmissionCompleted SubmissionStatus = "completed"
	SubmissionFailed    SubmissionStatus = "failed"
)

// ProviderSummary summarizes provider run counts on the submission status response (#75).
type ProviderSummary struct {
	Selected   int `json:"selected"`
	Completed  int `json:"completed"`
	Failed     int `json:"failed"`
	TimedOut   int `json:"timedOut"`
	Incomplete int `json:"incomplete"`
}

// Submission represents the state and result references of an artifact submission (#66, #67, #75).
type Submission struct {
	SchemaVersion     string           `json:"schemaVersion"`
	ID                string           `json:"id"`
	Status            SubmissionStatus `json:"status"`
	AcceptedAt        time.Time        `json:"acceptedAt"`
	CompletedAt       *time.Time       `json:"completedAt,omitempty"`
	Artifact          ArtifactInput    `json:"artifact"`
	Policy            PolicyReportRef  `json:"policy"`
	ProviderSummary   *ProviderSummary `json:"providerSummary,omitempty"`
	EvidenceStatus    EvidenceStatus   `json:"evidenceStatus,omitempty"`
	PolicyVerdict     PolicyVerdict    `json:"policyVerdict,omitempty"`
	AggregateReportID string           `json:"aggregateReportId,omitempty"`
	PolicyReportID    string           `json:"policyReportId,omitempty"`
	Error             string           `json:"error,omitempty"`
}

// ProblemDetails represents a structured HTTP error response (RFC 9457).
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}
