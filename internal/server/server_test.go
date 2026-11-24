// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
)

func newTestServer(t *testing.T) (*Server, *gateway.Orchestrator) {
	t.Helper()
	cfg := config.Default()
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "server-test.db"))
	store, err := gateway.OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	orch := gateway.NewOrchestrator(cfg, store)
	return New(cfg, store, orch), orch
}

func TestHealthAndReadyz(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Routes()

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d, want 200", path, rec.Code)
		}
	}
}

func TestSubmissionAndStatus(t *testing.T) {
	srv, orch := newTestServer(t)
	handler := srv.Routes()

	// 1. Validation failure (invalid PURL -> 422).
	badBody := []byte(`{"artifact":{"purl":"not-a-purl"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(badBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for invalid purl, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Valid submission (202 Accepted).
	validBody := []byte(`{"artifact":{"purl":"pkg:npm/lodash@4.17.20"}}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(validBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var created api.Submission
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	orch.Wait()

	// 3. Poll submission status (200 OK).
	req = httptest.NewRequest(http.MethodGet, "/v1/submissions/"+created.ID, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	var polled api.Submission
	if err := json.Unmarshal(rec.Body.Bytes(), &polled); err != nil {
		t.Fatal(err)
	}
	if polled.Status != api.SubmissionCompleted {
		t.Fatalf("expected completed status, got %q", polled.Status)
	}
}

func TestMultipartSubmission(t *testing.T) {
	srv, orch := newTestServer(t)
	handler := srv.Routes()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("purl", "pkg:npm/express@4.19.2")
	fw, err := mw.CreateFormFile("content", "express.tgz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("sample-package-bytes"))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for multipart upload, got %d: %s", rec.Code, rec.Body.String())
	}
	orch.Wait()
}
