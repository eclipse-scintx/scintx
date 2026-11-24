// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"fmt"
	"time"
)

// This file holds the lease methods of the SQL store, and the rule for which
// clock a lease uses. The methods were split out of sql_claim.go to keep
// each file small.

// Which clock does a lease use?
//
// A lease is only safe when every gateway compares it with the same clock.
// The formal proof showed what happens otherwise: a gateway whose clock runs
// ahead sees a live lease as expired and claims the row a second time.
//
// PostgreSQL is shared by all gateways, so its clock is the one to use. The
// two constants below wrap a query argument N into the expression "the
// database's time now, plus N seconds". The result is text in the same
// fixed-width format as formatTimestampUTC, so it compares correctly with
// the timestamps already stored.
//
// statement_timestamp() is the moment the server received the statement. It
// does not change while the statement runs, so one statement sees one time.
//
// SQLite has no clock of its own. A lease is stored as a wall-clock string
// (formatTimestampUTC). That string cannot carry the monotonic stopwatch the
// heartbeat uses. WallClockLeases tells the heartbeat to stop when the wall
// clock passes the deadline too, so a forward step cannot leave a worker
// running after the stored lease has already expired.
const (
	pgClockOpen  = `(to_char((statement_timestamp() + make_interval(secs => `
	pgClockClose = `)) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || '000Z')`
)

// The fenced lease statements. Each one only touches a "running" row that
// the given attempt owns.
const (
	// MAX and GREATEST keep the later of the stored lease and the new one,
	// so a renewal never moves the lease back. An empty lease_until sorts
	// before every timestamp, so "no lease" always gives way to the new one.
	renewLeaseSQLite   = `UPDATE submissions SET lease_until = MAX(lease_until, ?) WHERE id = ? AND status = 'running' AND attempts = ?`
	renewLeasePostgres = `UPDATE submissions SET lease_until = GREATEST(lease_until, ` + pgClockOpen + `$1` + pgClockClose + `) WHERE id = $2 AND status = 'running' AND attempts = $3`

	delayRetrySQLite   = `UPDATE submissions SET lease_until = ? WHERE id = ? AND status = 'running' AND attempts = ?`
	delayRetryPostgres = `UPDATE submissions SET lease_until = ` + pgClockOpen + `$1` + pgClockClose + ` WHERE id = $2 AND status = 'running' AND attempts = $3`

	releaseLeaseSQLite   = `UPDATE submissions SET lease_until = '' WHERE id = ? AND status = 'running' AND attempts = ?`
	releaseLeasePostgres = `UPDATE submissions SET lease_until = '' WHERE id = $1 AND status = 'running' AND attempts = $2`
)

// leaseArg returns the query argument that stands for the time "at + d",
// where "at" is the caller's reading of its own clock.
//
// For SQLite it is that time as text.
//
// For PostgreSQL it is a number of seconds, to be added to the database
// clock (see pgClockOpen). time.Since(at) is how OLD the caller's reading
// is. Taking the age away from the database's "now" gives the moment of the
// reading, as the database's clock saw it. Only a duration crosses from the
// gateway to the database, never a date. So it does not matter what time the
// gateway's clock shows. It only has to tick at the normal speed.
//
// The result can never be later than the caller meant: the statement reaches
// the database after the age was measured, never before.
func (s *SQLStore) leaseArg(at time.Time, d time.Duration) any {
	if !s.postgres {
		return formatTimestampUTC(at.Add(d))
	}
	return (d - time.Since(at)).Seconds()
}

// execLeaseUpdate runs one of the fenced lease statements above. If it
// changed no row, the caller does not own the submission any more and gets
// ErrStaleAttempt.
func (s *SQLStore) execLeaseUpdate(ctx context.Context, action, id string, attempt int, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s lease for %s: %w", action, id, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%w: cannot %s lease for %s at attempt %d", ErrStaleAttempt, action, id, attempt)
	}
	return nil
}

// WallClockLeases reports whether lease expiry follows the gateway wall clock.
// SQLite stores lease_until as a timestamp string, so it does. PostgreSQL
// does not: the database clock plus a duration is the authority, and a step
// of the gateway's wall clock must not expire that lease.
func (s *SQLStore) WallClockLeases() bool { return !s.postgres }

// RenewLease atomically extends lease_until for an active submission claim
// only if the row is still in "running" state with the matching attempt number.
// It never moves the lease back (see the Store interface).
func (s *SQLStore) RenewLease(ctx context.Context, id string, attempt int, now time.Time, leaseDuration time.Duration) error {
	query := renewLeaseSQLite
	if s.postgres {
		query = renewLeasePostgres
	}
	return s.execLeaseUpdate(ctx, "renew", id, attempt, query, s.leaseArg(now, leaseDuration), id, attempt)
}

// DelayRetry sets lease_until to now + delay for an active submission claim,
// so the next retry waits that long. It may move the lease back (see the
// Store interface).
func (s *SQLStore) DelayRetry(ctx context.Context, id string, attempt int, now time.Time, delay time.Duration) error {
	query := delayRetrySQLite
	if s.postgres {
		query = delayRetryPostgres
	}
	return s.execLeaseUpdate(ctx, "delay retry of", id, attempt, query, s.leaseArg(now, delay), id, attempt)
}

// ReleaseLease clears lease_until for an active "running" submission owned by
// the given attempt number when a worker is interrupted by graceful shutdown.
func (s *SQLStore) ReleaseLease(ctx context.Context, id string, attempt int) error {
	query := releaseLeaseSQLite
	if s.postgres {
		query = releaseLeasePostgres
	}
	return s.execLeaseUpdate(ctx, "release", id, attempt, query, id, attempt)
}
