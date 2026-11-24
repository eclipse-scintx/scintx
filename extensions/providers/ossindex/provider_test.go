// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package ossindex_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/extensions/providers/ossindex"
)

func TestOSSIndexAdapter_MissingCredentialsAndEvaluate(t *testing.T) {
	unconf := ossindex.NewAdapter(ossindex.Config{}, nil)
	st := unconf.CheckAvailability(context.Background())
	if st.Available || st.State != api.StateUnconfigured {
		t.Fatalf("expected unconfigured state when token is missing, got %+v", st)
	}
	if len(st.Reasons) == 0 || st.Reasons[0] != "missing_credentials" {
		t.Fatalf("expected missing_credentials reason, got %+v", st.Reasons)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || pass != "valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{
			"coordinates": "pkg:npm/lodash@4.17.20",
			"vulnerabilities": [{
				"id": "sonatype-2021-1234",
				"cve": "CVE-2021-23337",
				"title": "Command Injection",
				"cvssScore": 9.1
			}]
		}]`))
	}))
	defer srv.Close()

	adapter := ossindex.NewAdapter(ossindex.Config{BaseURL: srv.URL, Token: "valid-token"}, srv.Client())
	res, err := adapter.Evaluate(context.Background(), api.EvaluationRequest{
		SubmissionID:  "sub-1",
		ProviderRunID: "run-1",
		Artifact:      api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	})
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}
	findings := res.Report.Capabilities[api.CapabilityVulnerabilities].Findings
	if len(findings) != 1 || findings[0].Severity != api.SeverityCritical {
		t.Fatalf("expected 1 critical finding, got %+v", findings)
	}

	badAuth := ossindex.NewAdapter(ossindex.Config{BaseURL: srv.URL, Token: "wrong"}, srv.Client())
	_, err = badAuth.Evaluate(context.Background(), api.EvaluationRequest{
		Artifact: api.ArtifactInput{PURL: "pkg:npm/lodash@4.17.20"},
	})
	var aerr *api.AdapterError
	if !errors.As(err, &aerr) || aerr.Code != api.ErrAuthFailed {
		t.Fatalf("expected authentication_failed error, got %v", err)
	}
}
