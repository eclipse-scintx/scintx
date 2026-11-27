// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/blob/blobtest"
	"github.com/eclipse-scintx/scintx/internal/config"
	"github.com/eclipse-scintx/scintx/internal/gateway"
)

// These tests cover what happens to the bytes of an uploaded file: they are
// stored for the provider adapters, and they never outlive their submission.

// succeedingHook stands in for a provider adapter that always finishes. With
// no hook a submission fails closed, so tests that expect "completed" need it.
func succeedingHook(context.Context, api.Submission) error { return nil }

// newTestBlobs opens a file blob store in a fresh temporary directory.
func newTestBlobs(t *testing.T) *blobtest.Store {
	t.Helper()
	return blobtest.Open(t)
}

// newUploadServer builds a gateway on an in-memory database with the given
// blob store and upload size limit.
func newUploadServer(t *testing.T, blobs blob.Store, maxBytes int64) (http.Handler, *gateway.Orchestrator) {
	t.Helper()
	cfg := config.Default()
	cfg.Gateway.MaxContentBytes = maxBytes
	store := gateway.NewMemoryStore()
	orch := gateway.NewOrchestratorWithExecutor(cfg, store, blobs, succeedingHook)
	t.Cleanup(orch.Shutdown)
	return New(cfg, store, orch).Routes(), orch
}

// expectNothingOnDisk fails the test if a blob or a staging file is left.
// It looks at the directory itself, so a leaked file of any kind is found.
func expectNothingOnDisk(t *testing.T, blobs *blobtest.Store, when string) {
	t.Helper()
	if files := blobs.Files(t); len(files) != 0 {
		t.Fatalf("%s: expected an empty blob directory, found %v", when, files)
	}
}

// recordingBlobs keeps a copy of each blob at the moment it is deleted.
//
// A submission finishes within milliseconds in these tests, and its blob is
// deleted right away. So a test cannot look at the blob afterwards. This
// wrapper lets it check what was stored anyway.
type recordingBlobs struct {
	blob.Store
	mu      sync.Mutex
	deleted map[string][]byte
}

func (r *recordingBlobs) Delete(id string) error {
	if reader, err := r.Open(id); err == nil {
		data, _ := io.ReadAll(reader)
		_ = reader.Close()
		r.mu.Lock()
		r.deleted[id] = data
		r.mu.Unlock()
	}
	return r.Store.Delete(id)
}

// TestUploadIsStoredThenDeletedWhenFinished follows one upload end to end.
// The stored bytes must equal the uploaded bytes, and they must be gone as
// soon as the submission is finished.
func TestUploadIsStoredThenDeletedWhenFinished(t *testing.T) {
	disk := newTestBlobs(t)
	blobs := &recordingBlobs{Store: disk, deleted: map[string][]byte{}}
	handler, orch := newUploadServer(t, blobs, 1<<20)

	// 100 KiB spans several 32 KiB copy chunks, so chunk handling is covered.
	data := make([]byte, 100<<10)
	_, _ = io.ReadFull(&patternReader{}, data)
	rec := postMultipart(t, handler, "/v1/submissions", func(mw *multipart.Writer) {
		fw, _ := mw.CreateFormFile("content", "pkg.tgz")
		_, _ = fw.Write(data)
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var created api.Submission
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	orch.Wait() // The submission runs to "completed", which deletes the blob.

	blobs.mu.Lock()
	stored, wasStored := blobs.deleted[created.ID]
	blobs.mu.Unlock()
	if !wasStored || !bytes.Equal(stored, data) {
		t.Fatalf("stored bytes differ from the upload: stored=%v storedLen=%d uploadLen=%d", wasStored, len(stored), len(data))
	}
	expectNothingOnDisk(t, disk, "after the submission completed")
}

// TestRejectedUploadLeavesNothingOnDisk sends uploads that must be refused.
// Each one has already written bytes to disk by the time it is refused, so
// each one is a chance to leak a file.
func TestRejectedUploadLeavesNothingOnDisk(t *testing.T) {
	blobs := newTestBlobs(t)
	handler, _ := newUploadServer(t, blobs, 16)
	file := func(mw *multipart.Writer, data string) {
		fw, _ := mw.CreateFormFile("content", "pkg.tgz")
		_, _ = fw.Write([]byte(data))
	}
	cases := []struct {
		name  string
		want  int
		build func(*multipart.Writer)
	}{
		{"oversized file", http.StatusUnprocessableEntity, func(mw *multipart.Writer) { file(mw, "this is more than 16 bytes") }},
		{"empty file", http.StatusUnprocessableEntity, func(mw *multipart.Writer) { file(mw, "") }},
		{"unknown field after the file", http.StatusBadRequest, func(mw *multipart.Writer) {
			file(mw, "good bytes")
			_ = mw.WriteField("surprise", "x")
		}},
		{"second file", http.StatusBadRequest, func(mw *multipart.Writer) {
			file(mw, "good bytes")
			file(mw, "more bytes")
		}},
		{"file plus purl", http.StatusUnprocessableEntity, func(mw *multipart.Writer) {
			file(mw, "good bytes")
			_ = mw.WriteField("purl", "pkg:npm/x@1.0.0")
		}},
	}
	for _, tc := range cases {
		rec := postMultipart(t, handler, "/v1/submissions", tc.build)
		if rec.Code != tc.want {
			t.Fatalf("%s: expected %d, got %d: %s", tc.name, tc.want, rec.Code, rec.Body.String())
		}
		expectNothingOnDisk(t, blobs, tc.name)
	}

	// A client that disconnects in the middle of the file: the body just ends.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	file(mw, "good bytes")
	cut := body.Len() - 4 // Stop inside the file bytes, before the closing boundary.
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(body.Bytes()[:cut]))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("truncated upload: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	expectNothingOnDisk(t, blobs, "truncated upload")
}
