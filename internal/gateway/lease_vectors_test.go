// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// The lease vectors tie the Go stores to the formal model.
//
// The lease design is proven correct in Lean (see formal/ and section 3 of
// docs/ARCHITECTURE.md). Those proofs are about a MODEL of the store. They
// only say something about this code if the stores behave like the model.
//
// testdata/lease_vectors.json is printed by the model itself
// (formal/LeaseProof/Vectors.lean). It holds scenarios: lists of store
// calls, and after each call the row that the model says must result. The
// tests below replay every scenario against a real store and compare.
//
// If one of these tests fails, the store and the model disagree. Do not
// edit the JSON file by hand. Find out which side is wrong. Then fix the
// store, or change the model and run ./scripts/formal.sh, which checks the
// proofs again and rewrites the file.

// leaseVectorTick is the real time that one unit of model time stands for.
// It is huge on purpose. On PostgreSQL the lease follows the database's
// real clock, and the test itself takes a few milliseconds. Against one
// hour that does not matter.
const leaseVectorTick = time.Hour

// leaseVectors mirrors the JSON file.
type leaseVectors struct {
	LeaseDuration int             `json:"leaseDuration"`
	MaxAttempts   int             `json:"maxAttempts"`
	Scenarios     []leaseScenario `json:"scenarios"`
}

// leaseScenario is one list of store calls on one new submission.
type leaseScenario struct {
	// Boundary is true when some claim arrives at the exact moment a lease
	// ends. Only a store with an exact, injected clock can replay that.
	Boundary bool        `json:"boundary"`
	Steps    []leaseStep `json:"steps"`
}

// leaseStep is one store call and the row that the model expects after it.
type leaseStep struct {
	Op string `json:"op"`
	K  int    `json:"k"` // The attempt number the caller sends.
	T  int    `json:"t"` // The caller's clock value.
	D  int    `json:"d"` // The retry delay.
	I  int    `json:"i"` // The new interruptions count.

	OK            bool   `json:"ok"` // Whether the store accepts the call.
	Status        string `json:"status"`
	Attempts      int    `json:"attempts"`
	Interruptions int    `json:"interruptions"`
	Lease         *int   `json:"lease"` // nil means "no lease".
}

func TestLeaseVectorsMemory(t *testing.T) {
	runLeaseVectors(t, true, func() Store { return NewMemoryStore() })
}

func TestLeaseVectorsSQLite(t *testing.T) {
	store, err := OpenSQLStore("file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "vectors.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runLeaseVectors(t, true, emptied(t, store))
}

// TestLeaseVectorsPostgres is skipped without SCINTX_TEST_POSTGRES_URL (see
// postgres_test.go). The clock is not exact there: the lease follows the
// database's own clock.
func TestLeaseVectorsPostgres(t *testing.T) {
	runLeaseVectors(t, false, emptied(t, openPostgresTestStore(t)))
}

// emptied returns a function that deletes every row and hands the store
// back. A claim takes "the next" row, so each scenario needs an empty store.
func emptied(t *testing.T, store *SQLStore) func() Store {
	return func() Store {
		t.Helper()
		if _, err := store.db.Exec("DELETE FROM submissions"); err != nil {
			t.Fatalf("empty the store: %v", err)
		}
		return store
	}
}

// runLeaseVectors replays every scenario. newStore must return an empty
// store on every call. exactClock says whether the store uses the caller's
// clock values as they are (memory and SQLite do, PostgreSQL does not).
func runLeaseVectors(t *testing.T, exactClock bool, newStore func() Store) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "lease_vectors.json"))
	if err != nil {
		t.Fatalf("read the lease vectors: %v", err)
	}
	var vectors leaseVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse the lease vectors: %v", err)
	}
	if len(vectors.Scenarios) == 0 {
		t.Fatal("the lease vectors hold no scenario")
	}
	replayed := 0
	for n, scenario := range vectors.Scenarios {
		if scenario.Boundary && !exactClock {
			continue
		}
		replay := &leaseReplay{
			t:           t,
			store:       newStore(),
			id:          api.NewID("submission"),
			start:       time.Now(),
			lease:       time.Duration(vectors.LeaseDuration) * leaseVectorTick,
			maxAttempts: vectors.MaxAttempts,
			exactClock:  exactClock,
		}
		replay.run(n, scenario)
		replayed++
	}
	t.Logf("replayed %d of %d scenarios", replayed, len(vectors.Scenarios))
}
