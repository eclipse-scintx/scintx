// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/config"
)

// These tests cover the life of uploaded content: a provider can read it
// while the submission runs, and it is gone once the submission is finished.

// readingHook returns an execution hook that reads the submission's blob and
// counts how often it saw exactly want. Then it returns result(attempt).
// It reads through sub.Artifact.OpenContent when wired (#70), falling back to
// blobs.Open so both paths are verified.
func readingHook(blobs blob.Store, want []byte, goodReads *atomic.Int32, result func(attempt int) error) hookFunc {
	return func(_ context.Context, sub api.Submission) error {
		var (
			reader io.ReadCloser
			err    error
		)
		if sub.Artifact.OpenContent != nil {
			reader, err = sub.Artifact.OpenContent()
		} else {
			reader, err = blobs.Open(sub.ID)
		}
		if err != nil {
			return err
		}
		got, err := io.ReadAll(reader)
		_ = reader.Close() // Close before the worker deletes the blob.
		if err == nil && bytes.Equal(got, want) {
			goodReads.Add(1)
		}
		return result(sub.Attempts)
	}
}

func TestContentIsReadableWhileRunningAndDeletedWhenFinished(t *testing.T) {
	data := []byte("uploaded package bytes")
	cases := []struct {
		name    string
		hookErr error
		want    api.SubmissionStatus
	}{
		{"completed", nil, api.SubmissionCompleted},
		{"failed", errors.New("the provider rejected the file"), api.SubmissionFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blobs, store := newTestBlobs(t), NewMemoryStore()
			var goodReads atomic.Int32
			hook := readingHook(blobs, data, &goodReads, func(int) error { return tc.hookErr })
			orch := newOrchestrator(config.Default(), store, withTestSettings(0, 0, hook), withBlobs(blobs))
			defer orch.Shutdown()

			sub := submitContent(t, orch, data)
			waitForStatus(t, store, sub.ID, tc.want)
			if goodReads.Load() != 1 {
				t.Fatalf("expected the hook to read the uploaded bytes once, got %d good reads", goodReads.Load())
			}
			expectNoLeftovers(t, blobs)
		})
	}
}

// TestContentIsKeptAcrossRetries checks that a retry still finds the bytes.
// Deleting them after the first failed attempt would break every retry.
func TestContentIsKeptAcrossRetries(t *testing.T) {
	data := []byte("retry me")
	blobs, store := newTestBlobs(t), NewMemoryStore()
	var goodReads atomic.Int32
	hook := readingHook(blobs, data, &goodReads, func(attempt int) error {
		if attempt == 1 {
			return fmt.Errorf("%w: provider answered 429", ErrRetryable)
		}
		return nil
	})
	orch := newOrchestrator(config.Default(), store, withTestSettings(0, 0, hook),
		// The poll timer finds the retry. Keep it as short as the backoff.
		withRetryBackoff(5*time.Millisecond), withPollInterval(5*time.Millisecond), withBlobs(blobs))
	defer orch.Shutdown()

	sub := submitContent(t, orch, data)
	waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	if goodReads.Load() != 2 {
		t.Fatalf("expected both attempts to read the uploaded bytes, got %d good reads", goodReads.Load())
	}
	expectNoLeftovers(t, blobs)
}

// TestContentSurvivesGracefulShutdown checks that a deploy in the middle of
// a scan keeps the bytes, so the next gateway instance can finish the scan.
func TestContentSurvivesGracefulShutdown(t *testing.T) {
	data := []byte("scan interrupted by a deploy")
	blobs, store := newTestBlobs(t), NewMemoryStore()
	started := make(chan struct{})
	var once sync.Once
	hook := func(execCtx context.Context, _ api.Submission) error {
		once.Do(func() { close(started) })
		<-execCtx.Done() // A long scan that the shutdown cuts short.
		return execCtx.Err()
	}
	orch := newOrchestrator(config.Default(), store, withTestSettings(0, 0, hook), withBlobs(blobs))
	sub := submitContent(t, orch, data)
	<-started
	shutCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	orch.ShutdownWithContext(shutCtx)
	cancel()

	// OpenContent is what a provider adapter calls. It must still work.
	reader, err := orch.OpenContent(sub.ID)
	if err != nil {
		t.Fatalf("expected the content to survive the shutdown: %v", err)
	}
	got, _ := io.ReadAll(reader)
	_ = reader.Close()
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q, want %q", got, data)
	}

	// The next instance finishes the scan, and only then are the bytes deleted.
	next := newOrchestrator(config.Default(), store, withTestSettings(0, 0, succeedingHook), withBlobs(blobs))
	defer next.Shutdown()
	waitForStatus(t, store, sub.ID, api.SubmissionCompleted)
	expectNoLeftovers(t, blobs)
}

// failingPutStore refuses every write, like a database that is down.
type failingPutStore struct{ Store }

func (failingPutStore) PutSubmission(context.Context, api.Submission) error {
	return errors.New("database is down")
}

// TestRefusedSubmissionLeavesNoContentBehind checks every way a submission
// with content can be refused. None of them may leave bytes on disk.
func TestRefusedSubmissionLeavesNoContentBehind(t *testing.T) {
	ctx := context.Background()
	data := []byte("never accepted")
	blobs := newTestBlobs(t)
	orch := newOrchestrator(config.Default(), NewMemoryStore(), withBlobs(blobs))
	defer orch.Shutdown()

	// 1. The measured facts fail validation (an empty file).
	_, err := orch.SubmitWithContent(ctx, api.ArtifactInput{Upload: contentMeta(nil)}, stageUpload(t, orch, nil))
	if !errors.Is(err, api.ErrValidation) {
		t.Fatalf("expected a validation error for an empty upload, got %v", err)
	}
	// 2. Bytes without metadata, and 3. metadata without bytes.
	if _, err := orch.SubmitWithContent(ctx, api.ArtifactInput{PURL: "pkg:npm/x@1.0.0"}, stageUpload(t, orch, data)); err == nil {
		t.Fatal("expected content without metadata to be refused")
	}
	if _, err := orch.Submit(ctx, api.ArtifactInput{Upload: contentMeta(data)}); err == nil {
		t.Fatal("expected metadata without content to be refused")
	}
	expectNoLeftovers(t, blobs)

	// 4. The database refuses the submission after the blob was committed.
	broken := newOrchestrator(config.Default(), failingPutStore{NewMemoryStore()}, withBlobs(blobs))
	defer broken.Shutdown()
	if _, err := broken.SubmitWithContent(ctx, api.ArtifactInput{Upload: contentMeta(data)}, stageUpload(t, broken, data)); err == nil {
		t.Fatal("expected the submission to fail when the database is down")
	}
	expectNoLeftovers(t, blobs)

	// 5. Without a blob store, uploads are refused as a storage error.
	disabled := newOrchestrator(config.Default(), NewMemoryStore())
	defer disabled.Shutdown()
	if _, err := disabled.NewUpload(); !errors.Is(err, blob.ErrStorage) {
		t.Fatalf("expected ErrStorage without a blob store, got %v", err)
	}
}
