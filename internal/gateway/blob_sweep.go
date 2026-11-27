// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"log/slog"
	"time"

	"github.com/eclipse-scintx/scintx/internal/blob"
)

// This file holds the blob sweeper. It is the safety net behind the normal
// "delete when the submission finishes" path in outcome.go.
//
// That normal path misses three cases, and the sweeper covers them:
//
//  1. The gateway crashed in the middle of an upload. A staging file is left.
//  2. The gateway crashed after storing a blob but before writing its
//     submission row. A blob with no submission is left.
//  3. A submission became "failed" without a worker running it. The store
//     does this when a submission is out of attempts. The blob is left.

const (
	// defaultSweepInterval is how often the sweeper runs.
	defaultSweepInterval = time.Minute
	// defaultOrphanGrace is how old a blob with no submission row must be
	// before it is deleted. For a moment during every upload this state is
	// normal: the blob is stored first and the row is written right after.
	// The grace period keeps the sweeper away from those in-flight uploads.
	defaultOrphanGrace = 5 * time.Minute
	// defaultStaleUploadAge is how long a staging file may sit unwritten
	// before it is deleted. It must stay longer than the upload read timeout
	// of the HTTP server (5 minutes), or a slow upload could lose its file.
	defaultStaleUploadAge = 15 * time.Minute
)

// sweepLoop runs one sweep at startup and then one per sweepInterval, until
// shutdown. The startup sweep cleans up after a crash of the last process.
func (o *Orchestrator) sweepLoop() {
	defer o.wg.Done()
	ticker := time.NewTicker(o.sweepInterval)
	defer ticker.Stop()
	for {
		o.sweepBlobs(o.workerCtx)
		select {
		case <-o.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// sweepBlobs deletes every stale staging file and every blob that is no
// longer needed. Errors are logged and the next sweep simply tries again.
func (o *Orchestrator) sweepBlobs(ctx context.Context) {
	staleUploads, err := o.blobs.RemoveStaleUploads(o.staleUploadAge)
	if err != nil {
		slog.Warn("blob sweep: removing stale uploads failed", "error", err)
	}
	entries, err := o.blobs.List()
	if err != nil {
		slog.Warn("blob sweep: listing blobs failed", "error", err)
		return
	}
	deleted := 0
	for _, entry := range entries {
		if o.blobIsNeeded(ctx, entry) {
			continue
		}
		if err := o.blobs.Delete(entry.ID); err != nil {
			slog.Warn("blob sweep: deleting a blob failed", "id", entry.ID, "error", err)
			continue
		}
		deleted++
	}
	if staleUploads > 0 || deleted > 0 {
		slog.Info("blob sweep removed leftover content", "staleUploads", staleUploads, "blobs", deleted)
	}
}

// blobIsNeeded reports whether a blob must be kept.
func (o *Orchestrator) blobIsNeeded(ctx context.Context, entry blob.Entry) bool {
	sub, found, err := o.store.GetSubmission(ctx, entry.ID)
	switch {
	case err != nil:
		// We could not ask the database. Never delete on a guess: keep the
		// blob and look again on the next sweep.
		return true
	case !found:
		// No submission owns this blob. It is either an upload that is being
		// accepted right now, or a leftover from a crash. Age tells them apart.
		return time.Since(entry.ModTime) < o.orphanGrace
	default:
		// A finished submission never runs again, so its bytes are not needed.
		return !sub.Status.IsTerminal()
	}
}
