// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/eclipse-scintx/scintx/adapter"
	"github.com/eclipse-scintx/scintx/api"
)

// This file holds helpers for the adapter execution tests (#97).

// mustSubmit submits an artifact and stops the test when the submit fails.
// The tests used to drop this error. A failed submit then showed up later as
// a confusing status timeout on an empty submission ID.
func mustSubmit(t *testing.T, orch *Orchestrator, artifact api.ArtifactInput) api.Submission {
	t.Helper()
	sub, err := orch.Submit(context.Background(), artifact)
	if err != nil {
		t.Fatalf("Submit(%+v) failed: %v", artifact, err)
	}
	return sub
}

// vulnFindingIDs decodes one stored ProviderReport and returns the IDs of all
// findings in it, across every capability and check.
func vulnFindingIDs(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var rep adapter.ProviderReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal provider report: %v", err)
	}
	var ids []string
	for _, capRep := range rep.Capabilities {
		for _, check := range capRep.Checks {
			for _, f := range check.Findings {
				ids = append(ids, f.ID)
			}
		}
	}
	return ids
}
