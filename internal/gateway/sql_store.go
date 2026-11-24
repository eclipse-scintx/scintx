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
	accepted_at   TEXT NOT NULL,
	completed_at TEXT,
	payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
`

// SQLStore persists submissions in SQLite or PostgreSQL via database/sql.
type SQLStore struct {
	db       *sql.DB
	postgres bool
}

// OpenSQLStore opens a SQLite or PostgreSQL database connection, configures
// connection pooling/WAL settings, and ensures the schema exists.
func OpenSQLStore(dsn string) (*SQLStore, error) {
	lower := strings.ToLower(strings.TrimSpace(dsn))
	isPostgres := strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://")

	driver := "sqlite"
	normalizedDSN := dsn
	if isPostgres {
		driver = "pgx"
	} else {
		if err := ensureSQLiteDir(dsn); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open(driver, normalizedDSN)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", driver, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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

// PutSubmission upserts a submission record into SQLite or PostgreSQL.
func (s *SQLStore) PutSubmission(ctx context.Context, sub api.Submission) error {
	payload, err := json.Marshal(sub)
	if err != nil {
		return fmt.Errorf("marshal submission %s: %w", sub.ID, err)
	}

	acceptedAt := sub.AcceptedAt.UTC().Format(time.RFC3339Nano)
	var completedAt sql.NullString
	if sub.CompletedAt != nil {
		completedAt = sql.NullString{
			String: sub.CompletedAt.UTC().Format(time.RFC3339Nano),
			Valid:  true,
		}
	}

	query := `
INSERT INTO submissions (id, status, accepted_at, completed_at, payload_json)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	status       = excluded.status,
	accepted_at  = excluded.accepted_at,
	completed_at = excluded.completed_at,
	payload_json = excluded.payload_json
`
	if s.postgres {
		query = `
INSERT INTO submissions (id, status, accepted_at, completed_at, payload_json)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT(id) DO UPDATE SET
	status       = EXCLUDED.status,
	accepted_at  = EXCLUDED.accepted_at,
	completed_at = EXCLUDED.completed_at,
	payload_json = EXCLUDED.payload_json
`
	}

	_, err = s.db.ExecContext(ctx, query, sub.ID, string(sub.Status), acceptedAt, completedAt, string(payload))
	return err
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
