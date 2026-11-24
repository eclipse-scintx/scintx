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
	"os"
	"path/filepath"
	"strings"
	"time"

	// Register pure-Go PostgreSQL and SQLite database/sql drivers.
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/yeeth-security/scintx/api"
)

const createSubmissionsTableSQL = `
CREATE TABLE IF NOT EXISTS submissions (
	id           TEXT PRIMARY KEY,
	status       TEXT NOT NULL,
	attempts     INTEGER NOT NULL DEFAULT 0,
	lease_until  TEXT NOT NULL DEFAULT '',
	accepted_at  TEXT NOT NULL,
	completed_at TEXT,
	payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_claimable ON submissions(status, lease_until);
`

// SQLStore persists submissions in SQLite or PostgreSQL via database/sql and
// implements lease-based work claiming so in-flight submissions automatically
// recover across gateway restarts without a separate recovery service.
type SQLStore struct {
	db       *sql.DB
	postgres bool
}

// OpenSQLStore opens a SQLite or PostgreSQL database connection, verifies
// connectivity, configures connection pooling/WAL settings, and ensures the
// schema exists.
func OpenSQLStore(dsn string) (*SQLStore, error) {
	lower := strings.ToLower(strings.TrimSpace(dsn))
	isPostgres := strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://")

	driver := "sqlite"
	if isPostgres {
		driver = "pgx"
	} else {
		if err := ensureSQLiteDir(dsn); err != nil {
			return nil, err
		}
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
		// SQLite supports one writer at a time; enable WAL and busy_timeout.
		db.SetMaxOpenConns(1)
		if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("configure sqlite pragmas: %w", err)
		}
	}

	if _, err := db.ExecContext(ctx, createSubmissionsTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize submissions schema: %w", err)
	}

	return &SQLStore{
		db:       db,
		postgres: isPostgres,
	}, nil
}

// PutSubmission inserts a new submission or applies a validated state
// transition inside a transaction, failing closed on illegal state transitions.
func (s *SQLStore) PutSubmission(ctx context.Context, sub api.Submission) error {
	if !sub.Status.IsValid() {
		return fmt.Errorf("invalid submission status %q", sub.Status)
	}

	payload, err := json.Marshal(sub)
	if err != nil {
		return fmt.Errorf("marshal submission %s: %w", sub.ID, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	selectQuery := `SELECT status, lease_until FROM submissions WHERE id = ?`
	if s.postgres {
		selectQuery = `SELECT status, lease_until FROM submissions WHERE id = $1 FOR UPDATE`
	}

	var (
		currentStatusStr string
		leaseUntil       string
	)
	err = tx.QueryRowContext(ctx, selectQuery, sub.ID).Scan(&currentStatusStr, &leaseUntil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check current status for %s: %w", sub.ID, err)
	}

	currentStatus := api.SubmissionStatus(currentStatusStr)
	if !api.CanTransition(currentStatus, sub.Status) {
		return fmt.Errorf("invalid submission state transition for %s: %q -> %q", sub.ID, currentStatus, sub.Status)
	}

	if sub.Status.IsTerminal() {
		leaseUntil = ""
	}

	acceptedAt := sub.AcceptedAt.UTC().Format(time.RFC3339Nano)
	var completedAt sql.NullString
	if sub.CompletedAt != nil {
		completedAt = sql.NullString{
			String: sub.CompletedAt.UTC().Format(time.RFC3339Nano),
			Valid:  true,
		}
	}

	upsertQuery := `
INSERT INTO submissions (id, status, attempts, lease_until, accepted_at, completed_at, payload_json)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	status       = excluded.status,
	attempts     = excluded.attempts,
	lease_until  = excluded.lease_until,
	accepted_at  = excluded.accepted_at,
	completed_at = excluded.completed_at,
	payload_json = excluded.payload_json
`
	if s.postgres {
		upsertQuery = `
INSERT INTO submissions (id, status, attempts, lease_until, accepted_at, completed_at, payload_json)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT(id) DO UPDATE SET
	status       = EXCLUDED.status,
	attempts     = EXCLUDED.attempts,
	lease_until  = EXCLUDED.lease_until,
	accepted_at  = EXCLUDED.accepted_at,
	completed_at = EXCLUDED.completed_at,
	payload_json = EXCLUDED.payload_json
`
	}

	if _, err := tx.ExecContext(ctx, upsertQuery,
		sub.ID, string(sub.Status), sub.Attempts, leaseUntil, acceptedAt, completedAt, string(payload),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// GetSubmission retrieves a submission record by ID from SQLite or PostgreSQL.
func (s *SQLStore) GetSubmission(ctx context.Context, id string) (api.Submission, bool, error) {
	query := `SELECT payload_json FROM submissions WHERE id = ?`
	if s.postgres {
		query = `SELECT payload_json FROM submissions WHERE id = $1`
	}

	var payload string
	err := s.db.QueryRowContext(ctx, query, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Submission{}, false, nil
	}
	if err != nil {
		return api.Submission{}, false, err
	}

	var sub api.Submission
	if err := json.Unmarshal([]byte(payload), &sub); err != nil {
		return api.Submission{}, false, fmt.Errorf("unmarshal submission %s: %w", id, err)
	}
	return sub, true, nil
}

// Ping checks connectivity to the SQL database.
func (s *SQLStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close closes the underlying sql.DB pool.
func (s *SQLStore) Close() error {
	return s.db.Close()
}

func ensureSQLiteDir(dsn string) error {
	path := strings.TrimPrefix(strings.TrimSpace(dsn), "file:")
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if path == "" || path == ":memory:" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
