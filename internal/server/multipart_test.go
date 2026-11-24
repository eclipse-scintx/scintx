// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/config"
	"github.com/eclipse-scintx/scintx/internal/gateway"
)

// postMultipart sends a multipart/form-data POST to target. The build
// callback writes the form parts.
func postMultipart(t *testing.T, handler http.Handler, target string, build func(*multipart.Writer)) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	build(mw)
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, target, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestMultipartIgnoresQueryString is the regression test for the query-string
// hole. r.FormValue used to read "?purl=..." too, so the URL could override
// the body and slip past the unknown-field check.
func TestMultipartIgnoresQueryString(t *testing.T) {
	srv, orch := newTestServer(t)
	handler := srv.Routes()
	const target = "/v1/submissions?purl=pkg:npm/from-query@1.0.0"

	// The body is empty, so the request has no artifact. The query must not count.
	rec := postMultipart(t, handler, target, func(*multipart.Writer) {})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 when the purl is only in the query string, got %d: %s", rec.Code, rec.Body.String())
	}

	// The body and the query disagree. The body must win.
	rec = postMultipart(t, handler, target, func(mw *multipart.Writer) {
		_ = mw.WriteField("purl", "pkg:npm/from-body@1.0.0")
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var created api.Submission
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Artifact.PURL != "pkg:npm/from-body@1.0.0" {
		t.Fatalf("expected the body purl to be used, got %q", created.Artifact.PURL)
	}
	orch.Wait()
}

func TestMultipartRejectsDuplicateAndMisplacedFields(t *testing.T) {
	srv, _ := newTestServer(t)
	handler := srv.Routes()

	// A repeated field used to be accepted, and the first value silently won.
	rec := postMultipart(t, handler, "/v1/submissions", func(mw *multipart.Writer) {
		_ = mw.WriteField("purl", "pkg:npm/first@1.0.0")
		_ = mw.WriteField("purl", "pkg:npm/second@1.0.0")
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate") {
		t.Fatalf("expected 400 duplicate field, got %d: %s", rec.Code, rec.Body.String())
	}

	// "content" must be a file part, and "purl" must be a plain text field.
	rec = postMultipart(t, handler, "/v1/submissions", func(mw *multipart.Writer) {
		_ = mw.WriteField("content", "not-a-file")
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a content text field, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = postMultipart(t, handler, "/v1/submissions", func(mw *multipart.Writer) {
		fw, _ := mw.CreateFormFile("purl", "purl.txt")
		_, _ = fw.Write([]byte("pkg:npm/a@1.0.0"))
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a purl file part, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMultipartUploadIsHashedAndSizeLimited(t *testing.T) {
	cfg := config.Default()
	cfg.Gateway.MaxContentBytes = 16 // A tiny limit keeps the test fast.
	store := gateway.NewMemoryStore()
	orch := gateway.NewOrchestratorWithBlobs(cfg, store, newTestBlobs(t))
	t.Cleanup(orch.Shutdown)
	handler := New(cfg, store, orch).Routes()

	upload := func(data []byte) *httptest.ResponseRecorder {
		return postMultipart(t, handler, "/v1/submissions", func(mw *multipart.Writer) {
			fw, _ := mw.CreateFormFile("content", "pkg.tgz")
			_, _ = fw.Write(data)
		})
	}

	// A file at the limit is accepted, and the stored hash matches the bytes.
	data := []byte("0123456789abcdef")
	rec := upload(data)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for an upload at the limit, got %d: %s", rec.Code, rec.Body.String())
	}
	var created api.Submission
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	meta := created.Artifact.ContentMeta
	if meta == nil || meta.SHA256 != hex.EncodeToString(sum[:]) || meta.SizeBytes != 16 || meta.Filename != "pkg.tgz" {
		t.Fatalf("unexpected content metadata: %+v", meta)
	}

	// One byte over the limit fails validation (422). An empty file does too.
	if rec := upload(append(data, 'x')); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for an oversized upload, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := upload(nil); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for an empty upload, got %d: %s", rec.Code, rec.Body.String())
	}
	orch.Wait()
}

// TestJSONRejectsClientContentMetadata checks that a JSON client cannot send
// the server-computed "contentMeta" object (#70). It used to be dropped without a word.
func TestJSONRejectsClientContentMetadata(t *testing.T) {
	srv, _ := newTestServer(t)
	body := []byte(`{"artifact":{"purl":"pkg:npm/x@1.0.0","contentMeta":{"sha256":"00","sizeBytes":5}}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for client-supplied content metadata, got %d: %s", rec.Code, rec.Body.String())
	}
}

// brokenStore fails every storage call with an error that contains a secret.
type brokenStore struct{ gateway.Store }

var errSecretDetail = errors.New("dial tcp db.internal:5432: password authentication failed for user scintx_admin")

func (brokenStore) Ping(context.Context) error { return errSecretDetail }
func (brokenStore) GetSubmission(context.Context, string) (api.Submission, bool, error) {
	return api.Submission{}, false, errSecretDetail
}
func (brokenStore) PutSubmission(context.Context, api.Submission) error { return errSecretDetail }

// TestStorageErrorsAreNotSentToClients checks that raw database errors stay
// in the log. /readyz needs no login, so a leak there is the most exposed.
func TestStorageErrorsAreNotSentToClients(t *testing.T) {
	cfg := config.Default()
	store := brokenStore{Store: gateway.NewMemoryStore()}
	orch := gateway.NewOrchestrator(cfg, store)
	t.Cleanup(orch.Shutdown)
	handler := New(cfg, store, orch).Routes()

	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/readyz", nil),
		httptest.NewRequest(http.MethodGet, "/v1/submissions/submission-"+strings.Repeat("0", 32), nil),
		httptest.NewRequest(http.MethodPost, "/v1/submissions", strings.NewReader(`{"artifact":{"purl":"pkg:npm/x@1.0.0"}}`)),
	}
	for _, req := range requests {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code < 500 {
			t.Fatalf("%s %s: expected a 5xx status, got %d", req.Method, req.URL.Path, rec.Code)
		}
		for _, secret := range []string{"db.internal", "scintx_admin", "password"} {
			if strings.Contains(rec.Body.String(), secret) {
				t.Fatalf("%s %s leaked %q: %s", req.Method, req.URL.Path, secret, rec.Body.String())
			}
		}
	}
}
