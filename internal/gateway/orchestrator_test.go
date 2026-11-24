// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
)

func TestOrchestratorSubmitAndStatus(t *testing.T) {
	cfg := config.Default()
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "test.db"))
	store, err := OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	orch := NewOrchestrator(cfg, store)

	sub, err := orch.Submit(context.Background(), api.ArtifactInput{
		PURL: "pkg:npm/lodash@4.17.20",
	})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	orch.Wait()

	finalSub, ok, err := store.GetSubmission(context.Background(), sub.ID)
	if err != nil {
		t.Fatalf("GetSubmission failed: %v", err)
	}
	if !ok {
		t.Fatal("expected submission in store")
	}
	if finalSub.Status != api.SubmissionCompleted {
		t.Fatalf("expected status completed, got %q", finalSub.Status)
	}
	if finalSub.CompletedAt == nil {
		t.Fatal("expected completedAt timestamp")
	}
}
