// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/eclipse-scintx/scintx/adapter"
)

func TestDescriptor(t *testing.T) {
	a := NewAdapter(Config{}, nil)
	d := a.Descriptor()

	if d.Slug != AdapterSlug || d.AdapterVersion != AdapterVersion || d.SupportedSchemaVersion != adapter.SchemaVersionV1 {
		t.Fatalf("unexpected descriptor identity: %+v", d)
	}
	if !slices.Equal(d.SupportedInputs.Types, []adapter.ArtifactInputType{adapter.InputTypePURL}) {
		t.Fatalf("unexpected input types: %+v", d.SupportedInputs.Types)
	}
	for _, eco := range []adapter.Ecosystem{
		adapter.EcosystemNPM, adapter.EcosystemPyPI, adapter.EcosystemGolang,
		adapter.EcosystemMaven, adapter.EcosystemVSCodeExtension,
	} {
		if !slices.Contains(d.SupportedInputs.Ecosystems, eco) {
			t.Fatalf("expected ecosystem %q in %v", eco, d.SupportedInputs.Ecosystems)
		}
	}
	if !slices.Equal(d.Capabilities[adapter.CapabilityVulnerabilities].Checks, []adapter.Check{adapter.CheckKnownVulnerabilities}) {
		t.Fatalf("unexpected vulnerabilities checks: %+v", d.Capabilities[adapter.CapabilityVulnerabilities])
	}
	if !slices.Equal(d.Capabilities[adapter.CapabilityThreats].Checks, []adapter.Check{adapter.CheckMalware}) {
		t.Fatalf("unexpected threats checks: %+v", d.Capabilities[adapter.CapabilityThreats])
	}
}

// TestQueryPaginationAndStubHydration verifies that Evaluate follows
// next_page_token across /v1/query pages and fetches full records from
// GET /v1/vulns/{id} whenever a query entry is a stub (#94, #98).
func TestQueryPaginationAndStubHydration(t *testing.T) {
	var vulnEndpointCalled bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-mirror-token" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == queryEndpoint:
			var q QueryRequest
			_ = json.NewDecoder(r.Body).Decode(&q)
			if q.PageToken == "" {
				_, _ = w.Write([]byte(`{"vulns":[{
					"schema_version":"1.6.0","id":"GHSA-35jh-r3h4-6jhm",
					"summary":"Command Injection in lodash","details":"lodash prior to 4.17.21 allows command injection.",
					"aliases":["CVE-2021-23337"],"related":["CGA-1234"],"upstream":["CVE-2021-23337"],
					"published":"2021-02-15T00:00:00Z","modified":"2023-01-01T00:00:00Z",
					"database_specific":{"severity":"HIGH"},
					"affected":[{"package":{"ecosystem":"npm","name":"lodash","purl":"pkg:npm/lodash"},"versions":["4.17.20"]}],
					"references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
				}],"next_page_token":"page-2"}`))
				return
			}
			if q.PageToken == "page-2" {
				// Return a stub record with only id and modified to exercise GET /v1/vulns/{id}.
				_, _ = w.Write([]byte(`{"vulns":[{"id":"MAL-2026-0001","modified":"2026-11-24T00:00:00Z"}]}`))
				return
			}
		case r.Method == http.MethodGet && r.URL.Path == vulnsEndpointPrefix+"MAL-2026-0001":
			vulnEndpointCalled = true
			_, _ = w.Write([]byte(`{
				"schema_version":"1.6.0","id":"MAL-2026-0001",
				"summary":"Malicious code in package","details":"Exfiltrates environment variables on install.",
				"aliases":["GHSA-malw-0001-0001"]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := NewAdapter(Config{
		BaseURL: srv.URL, RequireAuth: true, BearerToken: "test-mirror-token",
	}, srv.Client())

	res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		SubmissionID: "sub-1", ProviderRunID: "run-1",
		Artifact:              adapter.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities, adapter.CapabilityThreats},
	})
	if err != nil || !vulnEndpointCalled {
		t.Fatalf("Evaluate err=%v vulnEndpointCalled=%v", err, vulnEndpointCalled)
	}

	vulnCheck := res.Report.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities]
	if vulnCheck.Status != adapter.CheckStatusEvaluated || len(vulnCheck.Findings) != 1 {
		t.Fatalf("unexpected vulnerability check report: %+v", vulnCheck)
	}
	vf := vulnCheck.Findings[0]
	if vf.ID != "GHSA-35jh-r3h4-6jhm" || vf.Severity != adapter.SeverityHigh || vf.Type != adapter.FindingTypeVulnerability {
		t.Fatalf("unexpected vulnerability finding: %+v", vf)
	}
	if !slices.Equal(vf.Identifiers, []string{"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"}) {
		t.Fatalf("unexpected deduplicated identifiers: %v", vf.Identifiers)
	}
	if vf.Metadata[adapter.MetaKeyPublished] != "2021-02-15T00:00:00Z" || vf.Metadata[adapter.MetaKeyRelated] == nil {
		t.Fatalf("expected provenance metadata on finding, got %+v", vf.Metadata)
	}

	threatCheck := res.Report.Capabilities[adapter.CapabilityThreats].Checks[adapter.CheckMalware]
	if threatCheck.Status != adapter.CheckStatusEvaluated || len(threatCheck.Findings) != 1 {
		t.Fatalf("unexpected malware check report: %+v", threatCheck)
	}
	tf := threatCheck.Findings[0]
	if tf.ID != "MAL-2026-0001" || tf.Severity != adapter.SeverityCritical || tf.Type != adapter.FindingTypeMalware {
		t.Fatalf("unexpected hydrated malware finding: %+v", tf)
	}
	if len(res.RawProviderResponse) == 0 {
		t.Fatal("expected RawProviderResponse to be populated")
	}
}

// TestOpenVSXAndGolangFallbackMapping verifies PURL, ecosystem, and version
// mapping for pkg:vscode-extension, pkg:openvsx, dot-separated publisher.name
// coordinates, VSCode ecosystem fallback, and mixed-case Go modules (#96).
func TestOpenVSXAndGolangFallbackMapping(t *testing.T) {
	var queries []QueryRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q QueryRequest
		_ = json.NewDecoder(r.Body).Decode(&q)
		queries = append(queries, q)
		if q.Package != nil && q.Package.PURL != "" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if q.Package != nil && q.Package.Ecosystem == openVSXEcosystem && q.Package.Name == "acme.theme-pro" && q.Version == "1.0.2" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"MAL-2026-9999","summary":"Malicious Open VSX extension"}]}`))
			return
		}
		if q.Package != nil && q.Package.Ecosystem == vscodeEcosystem && q.Package.Name == "cline.agent" && q.Version == "3.1.3" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"MAL-2025-191157","summary":"Malicious VSCode extension"}]}`))
			return
		}
		if q.Package != nil && q.Package.Ecosystem == goOSVEcosystem && q.Package.Name == "github.com/Masterminds/vcs" && q.Version == "1.13.0" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"GO-2022-0414","summary":"Command injection in vcs"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	a := NewAdapter(Config{BaseURL: srv.URL}, srv.Client())
	for _, purl := range []string{
		"pkg:vscode-extension/acme/theme-pro@1.0.2",
		"pkg:vscode-extension/Acme/Theme-Pro@1.0.2?repository_url=https://open-vsx.org/",
		"pkg:vscode-extension/acme.theme-pro@1.0.2?repository_url=https%3A%2F%2Fopen-vsx.org",
	} {
		queries = nil
		res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
			Artifact:              adapter.ArtifactInput{PURL: purl},
			RequestedCapabilities: []adapter.Capability{adapter.CapabilityThreats},
		})
		if err != nil || len(queries) < 2 || len(res.Report.Capabilities[adapter.CapabilityThreats].Checks[adapter.CheckMalware].Findings) != 1 {
			t.Fatalf("%s: err=%v queries=%d", purl, err, len(queries))
		}
	}

	// Verify explicit repository_url=https://open-vsx.org does NOT fall back to parent "VSCode".
	queries = nil
	if res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:vscode-extension/cline/agent@3.1.3?repository_url=https://open-vsx.org"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityThreats},
	}); err != nil || len(queries) != 2 || len(res.Report.Capabilities[adapter.CapabilityThreats].Checks[adapter.CheckMalware].Findings) != 0 {
		t.Fatalf("expected repository_url=open-vsx.org to scope solely to Open VSX, err=%v queries=%d", err, len(queries))
	}

	// Verify unqualified pkg:vscode-extension falls back to parent "VSCode" ecosystem, and mixed-case "Go" works.
	if res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:vscode-extension/cline/agent@3.1.3"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityThreats},
	}); err != nil || len(res.Report.Capabilities[adapter.CapabilityThreats].Checks[adapter.CheckMalware].Findings) != 1 {
		t.Fatalf("expected VSCode parent ecosystem fallback finding, err=%v", err)
	}
	if res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:golang/github.com/Masterminds/vcs@v1.13.0"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	}); err != nil || len(res.Report.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities].Findings) != 1 {
		t.Fatalf("expected mixed-case Go fallback finding, err=%v", err)
	}
}
