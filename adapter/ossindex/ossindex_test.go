// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package ossindex

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/eclipse-scintx/scintx/adapter"
)

func TestDescriptorAndEndpointDefaults(t *testing.T) {
	a := NewAdapter(Config{}, nil)
	if a.cfg.BaseURL != DefaultBaseURL {
		t.Fatalf("expected DefaultBaseURL %q, got %q", DefaultBaseURL, a.cfg.BaseURL)
	}
	if DefaultBaseURL != "https://api.guide.sonatype.com" {
		t.Fatalf("unexpected Sonatype Guide Compatibility API default URL: %q", DefaultBaseURL)
	}

	d := a.Descriptor()
	if d.Slug != AdapterSlug || d.AdapterVersion != AdapterVersion || d.SupportedSchemaVersion != adapter.SchemaVersionV1 {
		t.Fatalf("unexpected descriptor identity: %+v", d)
	}
	if !slices.Equal(d.SupportedInputs.Types, []adapter.ArtifactInputType{adapter.InputTypePURL}) {
		t.Fatalf("unexpected input types: %+v", d.SupportedInputs.Types)
	}
	for _, eco := range []adapter.Ecosystem{
		adapter.EcosystemMaven, adapter.EcosystemNPM, adapter.EcosystemPyPI,
		adapter.EcosystemGolang, adapter.EcosystemCargo, adapter.EcosystemCocoapods,
		adapter.EcosystemConda, adapter.EcosystemRPM,
	} {
		if !slices.Contains(d.SupportedInputs.Ecosystems, eco) {
			t.Fatalf("expected ecosystem %q in %v", eco, d.SupportedInputs.Ecosystems)
		}
	}
	if !slices.Equal(d.Capabilities[adapter.CapabilityVulnerabilities].Checks, []adapter.Check{adapter.CheckKnownVulnerabilities}) {
		t.Fatalf("unexpected vulnerabilities checks: %+v", d.Capabilities[adapter.CapabilityVulnerabilities])
	}
}

// TestComponentReportAndGuidePATBasicAuth verifies that Evaluate sends
// preemptive HTTP Basic Auth when configured with a Sonatype Guide PAT (even
// when Username is omitted), strips PURL qualifiers/subpath from the upstream
// coordinate query, and normalizes component-report findings (#95, #96, #98).
func TestComponentReportAndGuidePATBasicAuth(t *testing.T) {
	var gotUser, gotPass string
	var gotAuthOk bool
	var gotReq ComponentReportRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotAuthOk = r.BasicAuth()
		if r.Method != http.MethodPost || r.URL.Path != componentReportEndpoint {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{
			"coordinates": "pkg:maven/org.apache.commons/commons-text@1.9",
			"reference": "https://ossindex.sonatype.org/component/pkg:maven/org.apache.commons/commons-text@1.9",
			"vulnerabilities": [{
				"id": "sonatype-2022-5432",
				"displayName": "SONATYPE-2022-5432",
				"title": "[CVE-2022-42889] CWE-94: Improper Control of Generation of Code",
				"description": "Apache Commons Text interpolation RCE.",
				"cvssScore": 9.8,
				"cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cwe": "CWE-94",
				"cve": "CVE-2022-42889",
				"reference": "https://ossindex.sonatype.org/vulnerability/sonatype-2022-5432",
				"versionRanges": ["[,1.10.0)"],
				"externalReferences": ["https://nvd.nist.gov/vuln/detail/CVE-2022-42889"]
			}]
		}]`))
	}))
	defer srv.Close()

	a := NewAdapter(Config{
		BaseURL: srv.URL,
		Token:   "sonatype_pat_test123",
	}, srv.Client())

	res, err := a.Evaluate(context.Background(), adapter.EvaluationRequest{
		SubmissionID:          "sub-1",
		ProviderRunID:         "run-1",
		Artifact:              adapter.ArtifactInput{PURL: "pkg:maven/org.apache.commons/commons-text@1.9?type=jar#sub"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !gotAuthOk || gotUser != defaultPATUsername || gotPass != "sonatype_pat_test123" {
		t.Fatalf("expected Basic Auth (%q, token), got ok=%v user=%q pass=%q", defaultPATUsername, gotAuthOk, gotUser, gotPass)
	}
	if !slices.Equal(gotReq.Coordinates, []string{"pkg:maven/org.apache.commons/commons-text@1.9"}) {
		t.Fatalf("expected minimized coordinate without qualifiers/subpath, got %v", gotReq.Coordinates)
	}

	vulnCheck := res.Report.Capabilities[adapter.CapabilityVulnerabilities].Checks[adapter.CheckKnownVulnerabilities]
	if vulnCheck.Status != adapter.CheckStatusEvaluated || len(vulnCheck.Findings) != 1 {
		t.Fatalf("unexpected check report: %+v", vulnCheck)
	}
	f := vulnCheck.Findings[0]
	if f.ID != "sonatype-2022-5432" || f.Severity != adapter.SeverityCritical || f.Type != adapter.FindingTypeVulnerability {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.Artifact == nil || f.Artifact.PURL != "pkg:maven/org.apache.commons/commons-text@1.9?type=jar#sub" {
		t.Fatalf("expected canonical artifact PURL preserved on finding, got %+v", f.Artifact)
	}
	wantIDs := []string{"sonatype-2022-5432", "CVE-2022-42889", "SONATYPE-2022-5432"}
	if !slices.Equal(f.Identifiers, wantIDs) {
		t.Fatalf("Identifiers = %v, want %v", f.Identifiers, wantIDs)
	}
	if f.Metadata[adapter.MetaKeyCVE] != "CVE-2022-42889" || f.Metadata[adapter.MetaKeyCWE] != "CWE-94" {
		t.Fatalf("expected CVE and CWE metadata, got %+v", f.Metadata)
	}
	if f.Metadata[adapter.MetaKeyComponentCoordinates] != "pkg:maven/org.apache.commons/commons-text@1.9" {
		t.Fatalf("expected componentCoordinates metadata, got %+v", f.Metadata)
	}
	if len(res.RawProviderResponse) == 0 {
		t.Fatal("expected RawProviderResponse to be populated")
	}
}

// TestExplicitBasicAuthAndCoordinateMinimization verifies explicit Username+Token
// Basic Auth, Go '@v' prefix stripping, and '~' pre-release version handling (#95, #96).
func TestExplicitBasicAuthAndCoordinateMinimization(t *testing.T) {
	var gotMethod, gotPath, gotUser, gotPass string
	var gotReq ComponentReportRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()
		if r.URL.Path == versionEndpoint {
			_, _ = w.Write([]byte(`{"version":"1-SNAPSHOT"}`))
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		_, _ = w.Write([]byte(`[{"coordinates":"pkg:golang/golang.org/x/text@0.3.7","vulnerabilities":[]}]`))
	}))
	defer srv.Close()

	basicAdapter := NewAdapter(Config{
		BaseURL:  srv.URL,
		Username: "dev@example.com",
		Token:    "legacy-or-pat-token",
	}, srv.Client())
	if st := basicAdapter.CheckAvailability(context.Background()); st.State != adapter.StateReady || !st.Available {
		t.Fatalf("expected ready with Username+Token, got %+v", st)
	}
	if gotMethod != http.MethodGet || gotPath != versionEndpoint {
		t.Fatalf("expected CheckAvailability to probe GET %s, got %s %s", versionEndpoint, gotMethod, gotPath)
	}
	if gotUser != "dev@example.com" || gotPass != "legacy-or-pat-token" {
		t.Fatalf("expected explicit Basic Auth user/token, got (%q, %q)", gotUser, gotPass)
	}

	// Verify Go '@v0.3.7' strips leading 'v' for upstream coordinate while keeping canonical PURL.
	if _, err := basicAdapter.Evaluate(context.Background(), adapter.EvaluationRequest{
		Artifact:              adapter.ArtifactInput{PURL: "pkg:golang/golang.org/x/text@v0.3.7"},
		RequestedCapabilities: []adapter.Capability{adapter.CapabilityVulnerabilities},
	}); err != nil {
		t.Fatalf("Evaluate Go @v0.3.7 failed: %v", err)
	}
	if !slices.Equal(gotReq.Coordinates, []string{"pkg:golang/golang.org/x/text@0.3.7"}) {
		t.Fatalf("expected '@v' prefix stripped in upstream coordinate, got %v", gotReq.Coordinates)
	}

	// Verify exact pre-release version containing '~' and '+incompatible' build metadata are mapped cleanly.
	if _, coord, err := validateAndMapPURL("pkg:rpm/fedora/openssl@3.0.8~rc1"); err != nil || coord != "pkg:rpm/fedora/openssl@3.0.8~rc1" {
		t.Fatalf("expected exact '~rc1' version to be accepted, got coord=%q err=%v", coord, err)
	}
	if _, coord, err := validateAndMapPURL("pkg:golang/github.com/dgrijalva/jwt-go@v3.2.0+incompatible"); err != nil || coord != "pkg:golang/github.com/dgrijalva/jwt-go@3.2.0+incompatible" {
		t.Fatalf("expected '@v' stripped and '+' preserved in coordinate, got coord=%q err=%v", coord, err)
	}
	// The 'v' prefix is stripped for Go and Composer only (#96).
	if _, coord, err := validateAndMapPURL("pkg:cargo/v8@v8"); err != nil || coord != "pkg:cargo/v8@v8" {
		t.Fatalf("expected '@v8' kept for cargo, got coord=%q err=%v", coord, err)
	}
}
