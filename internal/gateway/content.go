// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
)

// This file ties uploaded content to the life of its submission.
//
// The life of one blob:
//
//  1. NewUpload: the HTTP handler streams the upload into a staging file.
//  2. SubmitWithContent (submit.go): the staged bytes are committed under the
//     new submission ID, just before the submission row is written.
//  3. OpenContent: a provider adapter streams the bytes while it runs.
//  4. deleteContent: the blob is deleted the moment the submission reaches
//     "completed" or "failed" (see outcome.go).
//
// A blob is kept across retries and across a graceful shutdown, because the
// next attempt still needs it. Anything a crash leaves behind is removed by
// the sweeper in blob_sweep.go.

// withBlobs returns an option that installs the blob store.
func withBlobs(blobs blob.Store) orchestratorOption {
	return func(o *Orchestrator) { o.blobs = blobs }
}

// NewUpload starts a staged upload for the HTTP handler to stream into.
// The handler must pass it to SubmitWithContent or call Discard on it.
//
// Without a blob store the error wraps blob.ErrStorage. That makes the
// handler answer 500, which is right: it is a gateway setup problem and not
// something the client did wrong.
func (o *Orchestrator) NewUpload() (blob.Upload, error) {
	if o.blobs == nil {
		return nil, fmt.Errorf("%w: no blob store is configured, so content uploads are disabled", blob.ErrStorage)
	}
	return o.blobs.NewUpload()
}

// OpenContent returns a stream of the bytes uploaded for a submission. This
// is how a provider adapter reads the file it has to send to its provider.
//
// The caller must close the stream. Reading it does not load the file into
// memory, so adapters should copy from it instead of calling io.ReadAll.
// It returns blob.ErrNotFound when the submission has no stored content.
func (o *Orchestrator) OpenContent(submissionID string) (io.ReadCloser, error) {
	if o.blobs == nil {
		return nil, fmt.Errorf("%w: no blob store is configured", blob.ErrNotFound)
	}
	return o.blobs.Open(submissionID)
}

// deleteContent removes the stored bytes of a submission that no longer
// needs them. It does nothing for a submission without uploaded content.
//
// A failed delete is only logged. The sweeper finds the blob on its next
// pass and tries again, so the bytes still go away.
func (o *Orchestrator) deleteContent(sub api.Submission) {
	if o.blobs == nil || sub.Artifact.ContentMeta == nil {
		return
	}
	if err := o.blobs.Delete(sub.ID); err != nil {
		slog.Warn("deleting uploaded content failed; the sweeper will retry", "id", sub.ID, "error", err)
	}
}
