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

	"github.com/yeeth-security/scintx/api"
)

// ClaimNextSubmission atomically claims the oldest submission in "accepted" or
// "running" state whose lease is unset or expired (lease_until <= now).
// If the candidate has already reached maxAttempts, it is transitioned to
// terminal "failed" state inside the transaction so scans never get stuck.
func (s *SQLStore) ClaimNextSubmission(ctx context.Context, now time.Time, leaseDuration time.Duration, maxAttempts int) (api.Submission, bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	nowUTC := now.UTC()
	nowStr := formatTimestampUTC(nowUTC)
	leaseStr := formatTimestampUTC(nowUTC.Add(leaseDuration))

	for {
		sub, exhausted, found, err := s.claimOneCandidate(ctx, nowUTC, nowStr, leaseStr, maxAttempts)
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

// RenewLease atomically extends lease_until for an active submission claim
// only if the row is still in "running" state with the matching attempt number.
func (s *SQLStore) RenewLease(ctx context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error {
	newLease := formatTimestampUTC(now.UTC().Add(leaseDuration))
	query := `UPDATE submissions SET lease_until = ? WHERE id = ? AND status = 'running' AND attempts = ?`
	if s.postgres {
		query = `UPDATE submissions SET lease_until = $1 WHERE id = $2 AND status = 'running' AND attempts = $3`
	}

	res, err := s.db.ExecContext(ctx, query, newLease, id, attempt)
	if err != nil {
		return fmt.Errorf("renew lease for %s: %w", id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: cannot renew lease for %s at attempt %d", ErrStaleAttempt, id, attempt)
	}
	return nil
}

// ReleaseLease clears lease_until for an active "running" submission owned by
// the given attempt number when a worker is interrupted by graceful shutdown.
// This allows the next gateway instance to claim the submission immediately.
func (s *SQLStore) ReleaseLease(ctx context.Context, id string, attempt int) error {
	query := `UPDATE submissions SET lease_until = '' WHERE id = ? AND status = 'running' AND attempts = ?`
	if s.postgres {
		query = `UPDATE submissions SET lease_until = '' WHERE id = $1 AND status = 'running' AND attempts = $2`
	}

	res, err := s.db.ExecContext(ctx, query, id, attempt)
	if err != nil {
		return fmt.Errorf("release lease for %s: %w", id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: cannot release lease for %s at attempt %d", ErrStaleAttempt, id, attempt)
	}
	return nil
}

func (s *SQLStore) claimOneCandidate(ctx context.Context, nowUTC time.Time, nowStr, leaseStr string, maxAttempts int) (api.Submission, bool, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.Submission{}, false, false, err
	}
	defer func() { _ = tx.Rollback() }()

	findQuery := `
SELECT payload_json, attempts FROM submissions
WHERE status IN ('accepted', 'running') AND (lease_until = '' OR lease_until <= ?)
ORDER BY accepted_at ASC
LIMIT 1`
	if s.postgres {
		findQuery = `
SELECT payload_json, attempts FROM submissions
WHERE status IN ('accepted', 'running') AND (lease_until = '' OR lease_until <= $1)
ORDER BY accepted_at ASC
LIMIT 1
FOR UPDATE SKIP LOCKED`
	}

	var (
		payload      string
		prevAttempts int
	)
	err = tx.QueryRowContext(ctx, findQuery, nowStr).Scan(&payload, &prevAttempts)
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

	exhausted := sub.Attempts >= maxAttempts
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
		// Another worker claimed the candidate first; treat as exhausted/retry loop.
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
