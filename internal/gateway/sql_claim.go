// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// The two queries below find the next claimable row. They are named constants
// so the tests can check their query plans. The status filter is written
// exactly like the WHERE clause of idx_submissions_queue (see sql_store.go).
// That match is what lets the database use the index.
//
// Each query takes two arguments: the new lease, then "now" (see leaseArg in
// sql_lease.go for what they are in each dialect). It hands the new lease
// back as its third column. On SQLite that is just the argument again. On
// PostgreSQL it is the lease as the DATABASE's clock sees it. Reading it
// back lets one piece of Go code write the lease for both dialects, and it
// means the expiry check and the new lease use the very same "now".
const (
	findClaimableSQLite = `
SELECT payload_json, attempts, ? FROM submissions
WHERE status IN ('accepted', 'running') AND (lease_until = '' OR lease_until <= ?)
ORDER BY attempts ASC, accepted_at ASC
LIMIT 1`
	findClaimablePostgres = `
SELECT payload_json, attempts, ` + pgClockOpen + `$1` + pgClockClose + ` FROM submissions
WHERE status IN ('accepted', 'running') AND (lease_until = '' OR lease_until <= ` + pgClockOpen + `$2` + pgClockClose + `)
ORDER BY attempts ASC, accepted_at ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`
)

// ClaimNextSubmission atomically claims the next eligible submission in
// "accepted" or "running" state whose lease is unset or expired (lease_until <= now).
// Fresh submissions (lower attempts) are prioritized ahead of retries so
// transient retries never head-of-line block new submissions.
func (s *SQLStore) ClaimNextSubmission(ctx context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	for {
		sub, exhausted, found, err := s.claimOneCandidate(ctx, now, leaseDuration, maxAttempts)
		if err != nil {
			return api.Submission{}, false, err
		}
		if !found {
			return api.Submission{}, false, nil
		}
		if exhausted {
			// Candidate exceeded maxAttempts and was marked failed; check next candidate.
			continue
		}
		return sub, true, nil
	}
}

// RenewLease, DelayRetry and ReleaseLease are in sql_lease.go.

func (s *SQLStore) claimOneCandidate(ctx context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, bool, error) {
	// nowUTC only stamps the submission's own timestamps (such as
	// completedAt). The lease does not use it: see leaseArg.
	nowUTC := now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.Submission{}, false, false, err
	}
	defer func() { _ = tx.Rollback() }()

	findQuery := findClaimableSQLite
	if s.postgres {
		findQuery = findClaimablePostgres
	}

	var (
		payload      string
		prevAttempts int
		// leaseStr is the new lease, as the query hands it back.
		leaseStr string
	)
	err = tx.QueryRowContext(ctx, findQuery, s.leaseArg(now, leaseDuration), s.leaseArg(now, 0)).Scan(&payload, &prevAttempts, &leaseStr)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Submission{}, false, false, nil
	}
	if err != nil {
		return api.Submission{}, false, false, err
	}

	var sub api.Submission
	if err := json.Unmarshal([]byte(payload), &sub); err != nil {
		return api.Submission{}, false, false, err
	}

	// AttemptsExhausted leaves out attempts that a graceful shutdown cut
	// short, so deploys cannot use up a submission's attempt budget.
	exhausted := sub.AttemptsExhausted(maxAttempts)
	newLease := leaseStr
	var completedAt sql.NullString

	if exhausted {
		reason := fmt.Sprintf("submission exceeded maximum execution attempts (%d)", maxAttempts)
		if err := sub.TransitionTo(api.SubmissionFailed, reason, nowUTC); err != nil {
			return api.Submission{}, false, false, err
		}
		newLease = ""
		completedAt = sql.NullString{
			String: formatTimestampUTC(*sub.CompletedAt),
			Valid:  true,
		}
	} else {
		if err := sub.TransitionTo(api.SubmissionRunning, "", nowUTC); err != nil {
			return api.Submission{}, false, false, err
		}
		sub.Attempts++
	}

	newPayload, err := json.Marshal(sub)
	if err != nil {
		return api.Submission{}, false, false, err
	}

	// Guard the UPDATE with the previous attempt number so concurrent processes
	// cannot claim the same attempt simultaneously.
	updateQuery := `UPDATE submissions SET status = ?, attempts = ?, lease_until = ?, completed_at = ?, payload_json = ? WHERE id = ? AND attempts = ?`
	if s.postgres {
		updateQuery = `UPDATE submissions SET status = $1, attempts = $2, lease_until = $3, completed_at = $4, payload_json = $5 WHERE id = $6 AND attempts = $7`
	}
	res, err := tx.ExecContext(ctx, updateQuery,
		string(sub.Status), sub.Attempts, newLease, completedAt, string(newPayload), sub.ID, prevAttempts,
	)
	if err != nil {
		return api.Submission{}, false, false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return api.Submission{}, false, false, err
	}
	if rows == 0 {
		return api.Submission{}, true, true, nil
	}
	if err := tx.Commit(); err != nil {
		return api.Submission{}, false, false, err
	}
	return sub, exhausted, true, nil
}

// formatTimestampUTC formats a UTC time with fixed-width 9-digit nanoseconds
// so lexicographical string comparison in SQLite and PostgreSQL always matches
// chronological ordering.
func formatTimestampUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
