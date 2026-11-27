// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// These tests cover the blob sweeper: the safety net that removes content
// which the normal "delete when finished" path could not remove.

// putSubmissionInState stores a submission in the given status and returns
// its ID. It walks the real state machine to get there and saves after each
// step, because the store checks every state change against the saved row.
func putSubmissionInState(t *testing.T, store Store, status api.SubmissionStatus) string {
	t.Helper()
	now := time.Now().UTC()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		AcceptedAt:    now,
		Artifact:      api.ArtifactInput{ContentMeta: contentMeta([]byte("x"))},
	}
	for _, next := range []api.SubmissionStatus{api.SubmissionAccepted, api.SubmissionRunning, status} {
		if sub.Status == status {
			break
		}
		if err := sub.TransitionTo(next, "test", now); err != nil {
			t.Fatalf("transition to %q failed: %v", next, err)
		}
		if err := store.PutSubmission(context.Background(), sub); err != nil {
			t.Fatalf("PutSubmission(%q) failed: %v", next, err)
		}
	}
	return sub.ID
}

// commitBlob stores a small blob under id, with no submission logic at all.
func commitBlob(t *testing.T, blobs blob.Store, id string) {
	t.Helper()
	upload, err := blobs.NewUpload()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = upload.Write([]byte("leftover"))
	if err := upload.Commit(id); err != nil {
		t.Fatal(err)
	}
}

// newSweeper builds an Orchestrator that starts no goroutines. The tests
// call sweepBlobs on it by hand, so nothing else can touch the blobs.
func newSweeper(store Store, blobs blob.Store, orphanGrace time.Duration) *Orchestrator {
	return &Orchestrator{store: store, blobs: blobs, orphanGrace: orphanGrace, staleUploadAge: time.Hour}
}

func TestSweepDeletesOnlyBlobsThatAreNoLongerNeeded(t *testing.T) {
	blobs, store := newTestBlobs(t), NewMemoryStore()
	waiting := putSubmissionInState(t, store, api.SubmissionAccepted)
	running := putSubmissionInState(t, store, api.SubmissionRunning)
	completed := putSubmissionInState(t, store, api.SubmissionCompleted)
	failed := putSubmissionInState(t, store, api.SubmissionFailed)
	orphan := api.NewID("submission") // A blob whose submission row was never written.
	for _, id := range []string{waiting, running, completed, failed, orphan} {
		commitBlob(t, blobs, id)
	}

	// Finished submissions lose their blobs. Unfinished ones keep them. The
	// orphan is still young, so it could be an upload that is being accepted.
	newSweeper(store, blobs, time.Hour).sweepBlobs(context.Background())
	expectBlobs(t, blobs, waiting, running, orphan)

	// With no grace period left, the orphan counts as a crash leftover.
	newSweeper(store, blobs, 0).sweepBlobs(context.Background())
	expectBlobs(t, blobs, waiting, running)
}

// lookupFailsStore fails every read, like a database that is down.
type lookupFailsStore struct{ Store }

func (lookupFailsStore) GetSubmission(context.Context, string) (api.Submission, bool, error) {
	return api.Submission{}, false, errors.New("database is down")
}

// TestSweepKeepsBlobsWhenTheDatabaseIsDown checks that the sweeper never
// deletes on a guess. A database outage must not look like "no submission".
func TestSweepKeepsBlobsWhenTheDatabaseIsDown(t *testing.T) {
	blobs := newTestBlobs(t)
	id := api.NewID("submission")
	commitBlob(t, blobs, id)

	newSweeper(lookupFailsStore{NewMemoryStore()}, blobs, 0).sweepBlobs(context.Background())
	expectBlobs(t, blobs, id)
}

// staleAgeRecorder records the age that the sweeper asks to remove.
type staleAgeRecorder struct {
	blob.Store
	ages []time.Duration
}

func (r *staleAgeRecorder) RemoveStaleUploads(olderThan time.Duration) (int, error) {
	r.ages = append(r.ages, olderThan)
	return r.Store.RemoveStaleUploads(olderThan)
}

// TestSweepRemovesStaleUploads checks that every sweep also cleans the
// staging directory, using the configured age. (The removal itself is
// tested in the blob package.)
func TestSweepRemovesStaleUploads(t *testing.T) {
	recorder := &staleAgeRecorder{Store: newTestBlobs(t)}
	newSweeper(NewMemoryStore(), recorder, time.Hour).sweepBlobs(context.Background())
	if len(recorder.ages) != 1 || recorder.ages[0] != time.Hour {
		t.Fatalf("expected one stale-upload cleanup with age 1h, got %v", recorder.ages)
	}
}

// TestSweepLoopRunsInTheBackground checks that a real orchestrator starts
// the sweeper and that it keeps running without anyone calling it.
func TestSweepLoopRunsInTheBackground(t *testing.T) {
	blobs := newTestBlobs(t)
	orch := newOrchestrator(config.Default(), NewMemoryStore(), withBlobs(blobs),
		withSweepSettings(5*time.Millisecond, 0, time.Hour))
	defer orch.Shutdown()

	// Committed after startup, so only a later, periodic sweep can remove it.
	commitBlob(t, blobs, api.NewID("submission"))
	expectNoLeftovers(t, blobs)
}
