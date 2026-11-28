// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/eclipse-scintx/scintx/adapter"
)

// TestCleanReportProvenance verifies two things on a report with no findings.
// The recorded endpoint must not contain the base URL credentials. The report
// must list every fallback query that was sent, so a clean result still shows
// which names were checked (#98).
func TestCleanReportProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// Put credentials in the base URL, as a private mirror might.
	baseURL := strings.Replace(srv.URL, "http://", "http://user:secret@", 1)
	a := NewAdapter(Config{BaseURL: baseURL}, srv.Client())

	res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		ProviderRunID:         "run-1",
		Artifact:              adapter.ArtifactInput{PURL: "pkg:vscode-extension/Acme/Theme-Pro@1.0.2?repository_url=https://open-vsx.org"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityThreats},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	meta := res.Report.ResponseMetadata
	if got := meta[adapter.RespMetaKeyEndpoint]; got != srv.URL {
		t.Fatalf("endpoint = %v, want %q without credentials", got, srv.URL)
	}
	wantTried := []string{
		"VSCode:https://open-vsx.org/Acme.Theme-Pro",
		"VSCode:https://open-vsx.org/acme.theme-pro",
	}
	if tried, _ := meta[adapter.RespMetaKeyFallbackQueries].([]string); !slices.Equal(tried, wantTried) {
		t.Fatalf("fallbackQueries = %v, want %v", meta[adapter.RespMetaKeyFallbackQueries], wantTried)
	}
	// No fallback matched, so no matching ecosystem is recorded.
	if _, ok := meta[adapter.RespMetaKeyFallbackEcosystem]; ok {
		t.Fatalf("unexpected fallbackEcosystem on a clean report: %+v", meta)
	}
}
