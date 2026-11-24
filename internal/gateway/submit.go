// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
)

// This file holds the two ways to create a submission. Submit moved here
// from orchestrator.go when blob storage was added.

// Submit validates an artifact, persists a Submission in "accepted" state,
// and wakes an idle worker to claim and execute it immediately.
//
// It is for artifacts named by purl or digest only. An uploaded file goes
// through SubmitWithContent.
func (o *Orchestrator) Submit(ctx context.Context, artifact api.ArtifactInput) (api.Submission, error) {
	return o.SubmitWithContent(ctx, artifact, nil)
}

// SubmitWithContent is Submit for an artifact that may come with uploaded
// bytes. content is the staged upload from NewUpload. It is nil when the
// artifact has no upload.
//
// This call takes ownership of content. On success the bytes are stored
// under the new submission ID. On every error they are thrown away. The
// caller never has to clean up.
func (o *Orchestrator) SubmitWithContent(ctx context.Context, artifact api.ArtifactInput, content blob.Upload) (api.Submission, error) {
	if content != nil {
		// Discard does nothing after a successful Commit. So this one line
		// covers every early return below without leaking the staged bytes.
		defer content.Discard()
	}
	normArtifact, err := api.ValidateAndNormalizeArtifact(artifact, o.cfg.Gateway.MaxContentBytes)
	if err != nil {
		return api.Submission{}, err
	}
	// The metadata and the bytes must come as a pair. A submission that says
	// "I have content" with no stored bytes would mislead every provider.
	if (normArtifact.ContentMeta != nil) != (content != nil) {
		return api.Submission{}, errors.New("content metadata and content bytes must be given together")
	}
	now := time.Now().UTC()
	sub := api.Submission{
		SchemaVersion: api.SchemaVersionV1,
		ID:            api.NewID("submission"),
		AcceptedAt:    now,
		Artifact:      normArtifact,
	}
	if err := sub.TransitionTo(api.SubmissionAccepted, "", now); err != nil {
		return api.Submission{}, err
	}
	// Store the bytes BEFORE the submission row. A worker can claim the row
	// the moment it exists, and it must find the bytes already in place.
	if content != nil {
		if err := content.Commit(sub.ID); err != nil {
			return api.Submission{}, err
		}
	}
	if err := o.store.PutSubmission(ctx, sub); err != nil {
		// The submission was not accepted, so nobody will ever read its
		// bytes. Delete them now instead of leaving them for the sweeper.
		o.deleteContent(sub)
		return api.Submission{}, err
	}
	o.signalWake()
	return sub, nil
}
