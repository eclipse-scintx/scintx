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
	"strings"
	"testing"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
	"github.com/eclipse-scintx/scintx/internal/gateway"
)

func newTestServer(t *testing.T) (*Server, *gateway.Orchestrator) {
	t.Helper()
	cfg := config.Default()
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "server-test.db"))
	store, err := gateway.OpenStore(dsn)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	// A blob store is needed since uploads are stored (see upload_test.go).
	orch := gateway.NewOrchestratorWithBlobs(cfg, store, newTestBlobs(t))
	t.Cleanup(func() {
		orch.Shutdown()
		_ = store.Close()
	})
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

	// 4. Malformed submission ID on GET fails closed (400 Bad Request) before DB query.
	req = httptest.NewRequest(http.MethodGet, "/v1/submissions/not-a-valid-id", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid submission ID format, got %d", rec.Code)
	}

	// 5. Well-formed 128-bit (32 hex chars) but non-existent submission ID returns 404 Not Found.
	req = httptest.NewRequest(http.MethodGet, "/v1/submissions/submission-00000000000000000000000000000000", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown submission ID, got %d", rec.Code)
	}

	// 6. Structured digest object submission (#68, #70) succeeds (202 Accepted).
	digestBody := []byte(`{"artifact":{"digest":{"algorithm":"sha256","value":"` + strings.Repeat("a", 64) + `"}}}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(digestBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for valid digest object, got %d: %s", rec.Code, rec.Body.String())
	}
	orch.Wait()
}

func TestMultipartSubmission(t *testing.T) {
	srv, orch := newTestServer(t)
	handler := srv.Routes()

	// 1. Exclusive content upload succeeds (202 Accepted).
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
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

	// 2. Providing both purl and content in multipart fails closed (422).
	var bothBuf bytes.Buffer
	mw2 := multipart.NewWriter(&bothBuf)
	_ = mw2.WriteField("purl", "pkg:npm/express@4.19.2")
	fw2, err := mw2.CreateFormFile("content", "express.tgz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw2.Write([]byte("sample-package-bytes"))
	_ = mw2.Close()

	req2 := httptest.NewRequest(http.MethodPost, "/v1/submissions", &bothBuf)
	req2.Header.Set("Content-Type", mw2.FormDataContentType())
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 when both purl and content are supplied, got %d: %s", rec2.Code, rec2.Body.String())
	}

	// 3. Unknown multipart field fails closed (400 Bad Request).
	var unknownBuf bytes.Buffer
	mw3 := multipart.NewWriter(&unknownBuf)
	_ = mw3.WriteField("unexpected", "value")
	_ = mw3.Close()

	req3 := httptest.NewRequest(http.MethodPost, "/v1/submissions", &unknownBuf)
	req3.Header.Set("Content-Type", mw3.FormDataContentType())
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown multipart field, got %d: %s", rec3.Code, rec3.Body.String())
	}

	orch.Wait()
}
