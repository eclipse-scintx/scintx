// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"database/sql/driver"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPostgresDSN(t *testing.T) {
	cases := map[string]bool{
		"postgres://user:pw@localhost:5432/scintx":             true,
		"POSTGRESQL://localhost/scintx":                        true,
		"host=db user=scintx password=secret dbname=scintx":    true, // keyword/value style
		"  dbname=scintx sslmode=disable":                      true,
		"file:data/scintx.db":                                  false,
		"data/scintx.db":                                       false,
		"file:/data/host=1.db":                                 false, // "file:" always means SQLite
		`C:\data\host=1.db`:                                    false,
		"file:data/scintx.db?_pragma=busy_timeout(1)&mode=rwc": false,
	}
	for dsn, want := range cases {
		if got := isPostgresDSN(dsn); got != want {
			t.Errorf("isPostgresDSN(%q) = %v, want %v", dsn, got, want)
		}
	}
}

func TestSQLiteDSNWithPragmas(t *testing.T) {
	plain := sqliteDSNWithPragmas("file:data/scintx.db")
	if !strings.HasPrefix(plain, "file:data/scintx.db?_pragma=busy_timeout(5000)") {
		t.Fatalf("unexpected DSN: %s", plain)
	}
	// The caller's own query string goes last, so the operator's pragma wins.
	custom := sqliteDSNWithPragmas("file:data/scintx.db?_pragma=busy_timeout(1)")
	if !strings.HasSuffix(custom, "&_pragma=busy_timeout(1)") || strings.Count(custom, "?") != 1 {
		t.Fatalf("unexpected DSN: %s", custom)
	}
}

// TestSQLitePragmasApplyToEveryConnection is the regression test for pragmas
// that were set once on the first connection. The test throws that connection
// away and checks that a brand-new one still has the settings.
func TestSQLitePragmasApplyToEveryConnection(t *testing.T) {
	store, err := OpenSQLStore("file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "pragma.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	// Returning driver.ErrBadConn from Raw makes database/sql discard the connection.
	conn, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()

	want := map[string]string{"busy_timeout": "5000", "journal_mode": "wal", "synchronous": "1"}
	for pragma, expected := range want {
		var got string
		if err := store.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", pragma, err)
		}
		if got != expected {
			t.Errorf("PRAGMA %s = %q on a new connection, want %q", pragma, got, expected)
		}
	}
}

// TestSQLiteClaimQueryUsesQueueIndex checks the query plan of the claim
// query. With the old index SQLite had to sort the whole backlog on every
// claim, which shows up in the plan as "USE TEMP B-TREE FOR ORDER BY".
func TestSQLiteClaimQueryUsesQueueIndex(t *testing.T) {
	store, err := OpenSQLStore("file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "plan.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// The two arguments are the new lease, then "now" (see findClaimableSQLite).
	rows, err := store.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+findClaimableSQLite, "2026-01-01T00:01:00.000000000Z", "2026-01-01T00:00:00.000000000Z")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	if !strings.Contains(plan.String(), "idx_submissions_queue") || strings.Contains(plan.String(), "TEMP B-TREE") {
		t.Fatalf("claim query does not read idx_submissions_queue in order:\n%s", plan.String())
	}
}
