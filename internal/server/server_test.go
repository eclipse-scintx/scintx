// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package server_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/extensions/providers/ossindex"
	"github.com/yeeth-security/scintx/extensions/providers/osv"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
	"github.com/yeeth-security/scintx/internal/policy"
	"github.com/yeeth-security/scintx/internal/server"
)

func setupTestServer(t *testing.T) (*server.Server, *gateway.Orchestrator) {
	t.Helper()
	cfg := config.Default()
	store := gateway.NewStore()
	polMap, err := policy.LoadDir("../../policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	adapters := []api.ProviderAdapter{
		osv.NewAdapter(osv.Config{OfflineDemo: true}, nil),
		ossindex.NewAdapter(ossindex.Config{}, nil),
	}
	orch := gateway.NewOrchestrator(cfg, store, polMap, adapters)
	return server.New(cfg, store, orch), orch
}

func TestServer_ProbesSubmissionStatusReportsAndValidationFailure(t *testing.T) {
	srv, orch := setupTestServer(t)
	handler := srv.Routes()

	// 1. Liveness and readiness probes (#41).
	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d, want 200", path, rec.Code)
		}
	}

	// 2. Validation failure on invalid PURL (#41, #68).
	badReq := httptest.NewRequest(http.MethodPost, "/v1/submissions",
		strings.NewReader(`{"artifact":{"purl":"not-a-valid-purl"}}`))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d for invalid PURL, want 422", badRec.Code)
	}

	// 3. Valid JSON submission (#41, #68).
	goodReq := httptest.NewRequest(http.MethodPost, "/v1/submissions",
		strings.NewReader(`{"artifact":{"purl":"pkg:npm/lodash@4.17.20"},"policy":"baseline-security"}`))
	goodReq.Header.Set("Content-Type", "application/json")
	goodRec := httptest.NewRecorder()
	handler.ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusAccepted {
		t.Fatalf("got %d for valid submission, want 202: %s", goodRec.Code, goodRec.Body.String())
	}

	var created api.Submission
	if err := json.Unmarshal(goodRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	// 4. Poll status (#41, #67).
	pollReq := httptest.NewRequest(http.MethodGet, "/v1/submissions/"+created.ID, nil)
	pollRec := httptest.NewRecorder()
	handler.ServeHTTP(pollRec, pollReq)
	if pollRec.Code != http.StatusOK {
		t.Fatalf("got %d on poll, want 200", pollRec.Code)
	}
	var polled api.Submission
	_ = json.Unmarshal(pollRec.Body.Bytes(), &polled)
	if polled.Status != api.SubmissionCompleted || polled.PolicyVerdict != api.VerdictViolated {
		t.Fatalf("expected completed/violated submission, got %+v", polled)
	}

	// 5. Retrieve Aggregate Report and Policy Report (#67, #68).
	aggReq := httptest.NewRequest(http.MethodGet, "/v1/submissions/"+created.ID+"/aggregate-report", nil)
	aggRec := httptest.NewRecorder()
	handler.ServeHTTP(aggRec, aggReq)
	if aggRec.Code != http.StatusOK {
		t.Fatalf("got %d on aggregate-report, want 200", aggRec.Code)
	}

	polReq := httptest.NewRequest(http.MethodGet, "/v1/submissions/"+created.ID+"/policy-report", nil)
	polRec := httptest.NewRecorder()
	handler.ServeHTTP(polRec, polReq)
	if polRec.Code != http.StatusOK {
		t.Fatalf("got %d on policy-report, want 200", polRec.Code)
	}
	var polRep api.PolicyReport
	_ = json.Unmarshal(polRec.Body.Bytes(), &polRep)
	if polRep.PolicyVerdict != api.VerdictViolated || len(polRep.Violations) == 0 {
		t.Fatalf("expected violated policy report with violations, got %+v", polRep)
	}
}

func TestServer_OpenVSXMultipartSubmission(t *testing.T) {
	srv, orch := setupTestServer(t)
	handler := srv.Routes()

	var vsixBuf bytes.Buffer
	zw := zip.NewWriter(&vsixBuf)
	f, _ := zw.Create("extension/package.json")
	_, _ = f.Write([]byte(`{"publisher":"evil-pub","name":"malicious-ext","version":"1.0.0"}`))
	_ = zw.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("content", "malicious-ext-1.0.0.vsix")
	_, _ = part.Write(vsixBuf.Bytes())
	_ = mw.WriteField("mediaType", "application/octet-stream")
	_ = mw.WriteField("policy", "baseline-security")
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("got %d on multipart VSIX submission, want 202: %s", rec.Code, rec.Body.String())
	}

	var sub api.Submission
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	orch.Wait()

	polReq := httptest.NewRequest(http.MethodGet, "/v1/submissions/"+sub.ID+"/policy-report", nil)
	polRec := httptest.NewRecorder()
	handler.ServeHTTP(polRec, polReq)
	var polRep api.PolicyReport
	_ = json.Unmarshal(polRec.Body.Bytes(), &polRep)
	if polRep.PolicyVerdict != api.VerdictViolated {
		t.Fatalf("expected violated verdict for malicious VSIX, got %+v", polRep)
	}
}
