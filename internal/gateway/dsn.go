// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// This file holds the helpers that inspect and prepare a storage DSN.

// postgresKeywordDSN matches the PostgreSQL keyword/value DSN style, for
// example "host=db user=scintx password=secret dbname=scintx".
var postgresKeywordDSN = regexp.MustCompile(`(^|\s)(host|hostaddr|port|dbname|user|password|sslmode|service)\s*=`)

// isPostgresDSN reports whether dsn points at PostgreSQL.
//
// It accepts the URL style ("postgres://...") and the keyword/value style.
// Before, only the URL style was detected. A keyword/value DSN was then
// treated as a SQLite file name, which created a file whose name contained
// the database password.
func isPostgresDSN(dsn string) bool {
	lower := strings.ToLower(strings.TrimSpace(dsn))
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return true
	}
	// An explicit "file:" prefix always means SQLite, whatever the name holds.
	if strings.HasPrefix(lower, "file:") {
		return false
	}
	return postgresKeywordDSN.MatchString(lower)
}

// sqlitePragmaQuery configures WAL mode with synchronous=NORMAL, a 5 second
// busy timeout, in-memory temp tables, and a 32 MiB page cache.
//
// WAL with synchronous=NORMAL is much faster than the default and can never
// corrupt the database. It survives a crash or restart of the gateway process
// with nothing lost. The one trade-off: if the whole machine loses power, the
// last few committed writes may be rolled back.
// _txlock=immediate makes BEGIN take the write lock at the start of the
// transaction. Claim reads a row and then updates it. With the default
// deferred lock, another process can commit a "completed" write between
// those two statements. Immediate locking closes that window. The claim
// UPDATE also rechecks status and lease, so a lost race changes no row.
const sqlitePragmaQuery = "_txlock=immediate" +
	"&_pragma=busy_timeout(5000)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=temp_store(MEMORY)" +
	"&_pragma=cache_size(-32000)"

// sqliteDSNWithPragmas adds the pragmas above to dsn as "_pragma" query
// parameters. The SQLite driver then runs them on EVERY new connection.
//
// Before, the pragmas were run once with a single Exec after opening. Most
// of them only last for one connection. So if database/sql ever replaced the
// connection, the busy timeout and the other settings were silently lost.
//
// Our pragmas go first and the caller's own query string goes last, so a
// "_pragma" the operator sets in the DSN still wins.
func sqliteDSNWithPragmas(dsn string) string {
	base, query, _ := strings.Cut(strings.TrimSpace(dsn), "?")
	out := base + "?" + sqlitePragmaQuery
	if query != "" {
		out += "&" + query
	}
	return out
}

// ensureSQLiteDir creates the parent directory of a SQLite database file so
// a fresh install can start without a manual mkdir.
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
	// The path comes from the storage DSN, which the operator sets in the
	// configuration. No request can change it.
	return os.MkdirAll(dir, 0o750) //nolint:gosec // G703: trusted path, see above.
}
