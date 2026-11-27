// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

// This file holds the table and index definitions. It was split out of
// sql_store.go to keep each file small. The same SQL runs on SQLite and on
// PostgreSQL.

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
DROP INDEX IF EXISTS idx_submissions_claimable;
CREATE INDEX IF NOT EXISTS idx_submissions_queue
ON submissions(attempts, accepted_at) WHERE status IN ('accepted', 'running');`

// About the index above. The claim query filters on status and lease, then
// sorts by (attempts, accepted_at) and takes one row. The old index
// idx_submissions_claimable led with (status, lease_until), so it could not
// serve that sort. Every claim sorted the whole backlog.
//
// idx_submissions_queue is already in claim order, and it only holds rows
// that can still be claimed. The database now walks it from the start and
// stops at the first row whose lease is free. Finished rows are not in it at
// all. The old index is dropped because nothing uses it any more.
//
// The SQLite pragmas (WAL and friends) now live in dsn.go. They are passed in
// the DSN so they apply to every connection.
