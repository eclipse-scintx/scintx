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

	// Register pure-Go PostgreSQL and SQLite database/sql drivers.
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/eclipse-scintx/scintx/api"
)

// SQLStore persists submissions in SQLite or PostgreSQL via database/sql and
// implements lease-based work claiming and attempt fencing.
type SQLStore struct {
	db       *sql.DB
	postgres bool
}

// OpenSQLStore opens a SQLite or PostgreSQL database connection, configures
// high-throughput WAL/pooling settings, and initializes the schema.
func OpenSQLStore(dsn string) (*SQLStore, error) {
	isPostgres := isPostgresDSN(dsn)
	driver := "sqlite"
	if isPostgres {
		driver = "pgx"
	} else {
		if err := ensureSQLiteDir(dsn); err != nil {
			return nil, err
		}
		// Put the pragmas in the DSN so every connection gets them.
		dsn = sqliteDSNWithPragmas(dsn)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", driver, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping %s database: %w", driver, err)
	}
	if !isPostgres {
		// SQLite allows one writer at a time, so one connection is enough.
		//
		// This is also why SQLite is for ONE gateway process only. A claim
		// opens a normal (deferred) transaction that reads first and writes
		// second. When a second process holds the write lock in between,
		// SQLite refuses the upgrade at once with SQLITE_BUSY, and the busy
		// timeout does not help. Several gateway instances must share a
		// PostgreSQL database instead (see the README).
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(32)
		db.SetMaxIdleConns(16)
	}
	if _, err := db.ExecContext(ctx, createSubmissionsTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize submissions schema: %w", err)
	}
	return &SQLStore{db: db, postgres: isPostgres}, nil
}

// PutSubmission persists a new submission or applies a fenced state transition.
// To maximize throughput, initial "accepted" creation uses a single direct
// INSERT statement, and state transitions use a single atomic UPDATE guarded by
// both the attempt fencing token and allowed source states.
func (s *SQLStore) PutSubmission(ctx context.Context, sub api.Submission) error {
	if !sub.Status.IsValid() {
		return fmt.Errorf("invalid submission status %q", sub.Status)
	}
	payload, err := json.Marshal(sub)
	if err != nil {
		return fmt.Errorf("marshal submission %s: %w", sub.ID, err)
	}
	acceptedAt := formatTimestampUTC(sub.AcceptedAt)
	var completedAt sql.NullString
	if sub.CompletedAt != nil {
		completedAt = sql.NullString{String: formatTimestampUTC(*sub.CompletedAt), Valid: true}
	}

	// Fast path 1: Brand-new submission in "accepted" state (1 SQL statement).
	if sub.Status == api.SubmissionAccepted && sub.Attempts == 0 {
		query := `INSERT INTO submissions (id, status, attempts, lease_until, accepted_at, completed_at, payload_json) VALUES (?, ?, 0, '', ?, ?, ?)`
		if s.postgres {
			query = `INSERT INTO submissions (id, status, attempts, lease_until, accepted_at, completed_at, payload_json) VALUES ($1, $2, 0, '', $3, $4, $5)`
		}
		_, err := s.db.ExecContext(ctx, query, sub.ID, string(sub.Status), acceptedAt, completedAt, string(payload))
		return err
	}
	// "accepted" is only ever the first state. A submission that has been
	// claimed (attempts > 0) must never go back to it. Without this check the
	// generic UPDATE below moved a running row back to "accepted", which the
	// state machine forbids and which MemoryStore already refused.
	if sub.Status == api.SubmissionAccepted {
		return fmt.Errorf("invalid submission state transition for %s: a claimed submission cannot return to %q", sub.ID, sub.Status)
	}

	// Fast path 2: Atomic fenced UPDATE enforcing both state machine and attempt token.
	return s.execFencedTransition(ctx, sub, completedAt, string(payload))
}

func (s *SQLStore) execFencedTransition(ctx context.Context, sub api.Submission, completedAt sql.NullString, payload string) error {
	var query string
	if sub.Status == api.SubmissionCompleted {
		// Completed transitions are only valid from "running" and clear lease_until.
		query = `UPDATE submissions SET status = ?, attempts = ?, lease_until = '', completed_at = ?, payload_json = ? WHERE id = ? AND attempts = ? AND status = 'running'`
		if s.postgres {
			query = `UPDATE submissions SET status = $1, attempts = $2, lease_until = '', completed_at = $3, payload_json = $4 WHERE id = $5 AND attempts = $6 AND status = 'running'`
		}
	} else if sub.Status == api.SubmissionFailed {
		// Failed transitions are valid from "accepted" or "running" and clear lease_until.
		query = `UPDATE submissions SET status = ?, attempts = ?, lease_until = '', completed_at = ?, payload_json = ? WHERE id = ? AND attempts = ? AND status IN ('accepted', 'running')`
		if s.postgres {
			query = `UPDATE submissions SET status = $1, attempts = $2, lease_until = '', completed_at = $3, payload_json = $4 WHERE id = $5 AND attempts = $6 AND status IN ('accepted', 'running')`
		}
	} else {
		// Running transitions preserve lease_until and are valid from "accepted" or "running".
		query = `UPDATE submissions SET status = ?, attempts = ?, completed_at = ?, payload_json = ? WHERE id = ? AND attempts = ? AND status IN ('accepted', 'running')`
		if s.postgres {
			query = `UPDATE submissions SET status = $1, attempts = $2, completed_at = $3, payload_json = $4 WHERE id = $5 AND attempts = $6 AND status IN ('accepted', 'running')`
		}
	}
	res, err := s.db.ExecContext(ctx, query, string(sub.Status), sub.Attempts, completedAt, payload, sub.ID, sub.Attempts)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err != nil {
		return err
	} else if rows == 1 {
		return nil
	}
	return s.diagnoseTransitionFailure(ctx, sub)
}

func (s *SQLStore) diagnoseTransitionFailure(ctx context.Context, sub api.Submission) error {
	query := `SELECT status, attempts FROM submissions WHERE id = ?`
	if s.postgres {
		query = `SELECT status, attempts FROM submissions WHERE id = $1`
	}
	var currentStatusStr string
	var currentAttempts int
	err := s.db.QueryRowContext(ctx, query, sub.ID).Scan(&currentStatusStr, &currentAttempts)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && currentAttempts != sub.Attempts {
		return fmt.Errorf("%w: submission %s is at attempt %d, got %d", ErrStaleAttempt, sub.ID, currentAttempts, sub.Attempts)
	}
	return fmt.Errorf("invalid submission state transition for %s: %q -> %q", sub.ID, currentStatusStr, sub.Status)
}

// GetSubmission retrieves a submission record by ID from SQLite or PostgreSQL.
func (s *SQLStore) GetSubmission(ctx context.Context, id string) (api.Submission, bool, error) {
	query := `SELECT payload_json FROM submissions WHERE id = ?`
	if s.postgres {
		query = `SELECT payload_json FROM submissions WHERE id = $1`
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, query, id).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return api.Submission{}, false, nil
	} else if err != nil {
		return api.Submission{}, false, err
	}
	var sub api.Submission
	if err := json.Unmarshal([]byte(payload), &sub); err != nil {
		return api.Submission{}, false, fmt.Errorf("unmarshal submission %s: %w", id, err)
	}
	return sub, true, nil
}

// Ping checks connectivity to the SQL database.
func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close closes the underlying sql.DB pool.
func (s *SQLStore) Close() error { return s.db.Close() }
