// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/blob/blobtest"
)

// This file holds helpers shared by the blob tests (content_test.go and
// blob_sweep_test.go).

// withSweepSettings returns an option that sets the blob sweeper timings.
// Tests use tiny values so they do not wait out the one minute default.
func withSweepSettings(interval, orphanGrace, staleUploadAge time.Duration) orchestratorOption {
	return func(o *Orchestrator) {
		o.sweepInterval = interval
		o.orphanGrace = orphanGrace
		o.staleUploadAge = staleUploadAge
	}
}

// newTestBlobs opens a file blob store in a fresh temporary directory.
func newTestBlobs(t *testing.T) *blobtest.Store {
	t.Helper()
	return blobtest.Open(t)
}

// contentMeta returns the facts the HTTP handler would measure for data.
func contentMeta(data []byte) *api.ContentMetadata {
	sum := sha256.Sum256(data)
	return &api.ContentMetadata{SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(data))}
}

// stageUpload starts an upload and writes data into it, like the HTTP
// handler does while a request body streams in.
func stageUpload(t *testing.T, orch *Orchestrator, data []byte) blob.Upload {
	t.Helper()
	upload, err := orch.NewUpload()
	if err != nil {
		t.Fatalf("NewUpload failed: %v", err)
	}
	if _, err := upload.Write(data); err != nil {
		t.Fatalf("writing the upload failed: %v", err)
	}
	return upload
}

// submitContent submits data as an uploaded artifact and fails the test if
// the submission is refused.
func submitContent(t *testing.T, orch *Orchestrator, data []byte) api.Submission {
	t.Helper()
	upload := stageUpload(t, orch, data)
	sub, err := orch.SubmitWithContent(context.Background(), api.ArtifactInput{Upload: contentMeta(data)}, upload)
	if err != nil {
		t.Fatalf("SubmitWithContent failed: %v", err)
	}
	return sub
}

// blobIDs returns the sorted IDs of every committed blob.
func blobIDs(t *testing.T, blobs blob.Store) []string {
	t.Helper()
	entries, err := blobs.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	slices.Sort(ids)
	return ids
}

// expectBlobs fails the test unless exactly the wanted blobs exist.
func expectBlobs(t *testing.T, blobs blob.Store, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := blobIDs(t, blobs); !slices.Equal(got, want) {
		t.Fatalf("unexpected blobs on disk:\n got  %v\n want %v", got, want)
	}
}

// expectNoLeftovers waits until no blob and no staging file is left on disk.
// It polls because a worker deletes the blob just AFTER it saves the final
// status, so a test that only waited for the status can be a moment early.
//
// It looks at the directory itself (blobtest.Store.Files), so a leaked file
// of any kind is found.
func expectNoLeftovers(t *testing.T, blobs *blobtest.Store) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(blobs.Files(t)) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("files were left in the blob directory: %v", blobs.Files(t))
		}
		time.Sleep(2 * time.Millisecond)
	}
}
