// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// These tests run the PostgreSQL code path: the "$n" queries, FOR UPDATE
// SKIP LOCKED, and the partial index. Before they existed, no test and no CI
// job ever ran that code.
//
// They need a real server. Set SCINTX_TEST_POSTGRES_URL to a "postgres://"
// URL to run them, for example:
//
//	SCINTX_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable
//
// Without the variable they are skipped. CI sets it (see ci.yml).

// openPostgresTestStore opens a store inside a fresh, uniquely named schema
// and drops that schema when the test ends. Existing tables in the database
// are never touched.
func openPostgresTestStore(t *testing.T) *SQLStore {
	t.Helper()
	base := os.Getenv("SCINTX_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("set SCINTX_TEST_POSTGRES_URL to run the PostgreSQL tests")
	}
	parsed, err := url.Parse(base)
	if err != nil || !isPostgresDSN(base) {
		t.Fatalf("SCINTX_TEST_POSTGRES_URL must be a postgres:// URL: %v", err)
	}
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	schema := "scintx_test_" + api.RandHex()[:12]
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})

	// search_path makes every table of this store live in the test schema.
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	store, err := OpenSQLStore(parsed.String())
	if err != nil {
		t.Fatalf("OpenSQLStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if !store.postgres {
		t.Fatal("expected the PostgreSQL dialect to be selected")
	}
	return store
}

func TestStoreContractPostgres(t *testing.T) {
	runStoreContract(t, openPostgresTestStore(t))
}

// TestPostgresConcurrentClaimsAreExclusive lets many goroutines claim at the
// same time. Each submission must be handed out exactly once.
func TestPostgresConcurrentClaimsAreExclusive(t *testing.T) {
	store := openPostgresTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const total = 40
	for i := 0; i < total; i++ {
		sub := api.Submission{SchemaVersion: api.SchemaVersionV1, ID: api.NewID("submission"), Status: api.SubmissionAccepted, AcceptedAt: now, Artifact: api.ArtifactInput{PURL: "pkg:npm/a@1.0.0"}}
		if err := store.PutSubmission(ctx, sub); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	claimed := map[string]int{}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				sub, ok, err := store.ClaimNextSubmission(ctx, now, time.Minute, 3)
				if err != nil {
					t.Errorf("ClaimNextSubmission: %v", err)
					return
				}
				if !ok {
					return
				}
				mu.Lock()
				claimed[sub.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claimed) != total {
		t.Fatalf("expected %d distinct claims, got %d", total, len(claimed))
	}
	for id, count := range claimed {
		if count != 1 {
			t.Fatalf("submission %s was claimed %d times", id, count)
		}
	}
}

// TestPostgresOrchestratorEndToEnd runs the full submit-to-completed flow.
func TestPostgresOrchestratorEndToEnd(t *testing.T) {
	store := openPostgresTestStore(t)
	orch := NewOrchestrator(config.Default(), store)
	defer orch.Shutdown()
	sub, err := orch.Submit(context.Background(), api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"})
	if err != nil {
		t.Fatal(err)
	}
	got := waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if got.Attempts != 1 || got.CompletedAt == nil {
		t.Fatalf("unexpected final submission: %+v", got)
	}
}

// TestPostgresClaimQueryUsesQueueIndex checks the plan of the claim query.
//
// On a tiny table the planner picks a sequential or bitmap scan plus a sort,
// whatever indexes exist, because that is cheapest for a few rows. The test
// switches those choices off. The planner then uses an ordered index scan if
// one is possible at all. With the old index it was not possible, so a Sort
// step stayed in the plan.
func TestPostgresClaimQueryUsesQueueIndex(t *testing.T) {
	store := openPostgresTestStore(t)
	ctx := context.Background()
	conn, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, setting := range []string{"enable_seqscan", "enable_bitmapscan", "enable_sort"} {
		if _, err := conn.ExecContext(ctx, "SET "+setting+" = off"); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := conn.QueryContext(ctx, "EXPLAIN "+findClaimablePostgres, "2026-01-01T00:00:00.000000000Z")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	// An index scan in claim order needs no separate "Sort" step.
	if !strings.Contains(plan.String(), "idx_submissions_queue") || strings.Contains(plan.String(), "Sort") {
		t.Fatalf("claim query does not read idx_submissions_queue in order:\n%s", plan.String())
	}
}
