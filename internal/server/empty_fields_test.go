// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests cover one rule: an artifact field that is SENT counts, even
// when its value is empty.
//
// The rule matters because an artifact must have exactly one of purl,
// digest, or content. Before, an empty purl was treated like a purl that was
// never sent. So a request with an empty purl AND a digest was accepted, and
// the gateway quietly picked the digest. The client clearly meant to name a
// package and something went wrong on its side (an unset variable, for
// example). Guessing is the wrong answer to that. The request must fail.
//
// The published schema (schema/artifact.schema.json) already says so: an
// artifact has exactly one property, and a purl is a non-empty string.

// validSHA256 is a well-formed digest value (64 hex characters).
var validSHA256 = strings.Repeat("a", 64)

// postJSON sends a JSON create request and returns the response.
func postJSON(handler http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestJSONRejectsEmptyArtifactFields(t *testing.T) {
	srv, orch := newTestServer(t)
	handler := srv.Routes()
	digest := `{"algorithm":"sha256","value":"` + validSHA256 + `"}`

	rejected := map[string]string{
		"empty purl next to a digest":      `{"artifact":{"purl":"","digest":` + digest + `}}`,
		"blank purl next to a digest":      `{"artifact":{"purl":"  ","digest":` + digest + `}}`,
		"null purl next to a digest":       `{"artifact":{"purl":null,"digest":` + digest + `}}`,
		"null digest next to a purl":       `{"artifact":{"purl":"pkg:npm/x@1.0.0","digest":null}}`,
		"null contentMeta next to a purl":  `{"artifact":{"purl":"pkg:npm/x@1.0.0","contentMeta":null}}`,
		"empty purl alone":                 `{"artifact":{"purl":""}}`,
		"null purl alone":                  `{"artifact":{"purl":null}}`,
		"null digest alone":                `{"artifact":{"digest":null}}`,
		"empty digest object next to purl": `{"artifact":{"purl":"pkg:npm/x@1.0.0","digest":{}}}`,
		"null artifact":                    `{"artifact":null}`,
		"no artifact":                      `{}`,
	}
	for name, body := range rejected {
		if rec := postJSON(handler, body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: expected 422, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	// The rule must not reject good requests. One field, with a value.
	accepted := map[string]string{
		"purl only":   `{"artifact":{"purl":"pkg:npm/x@1.0.0"}}`,
		"digest only": `{"artifact":{"digest":` + digest + `}}`,
	}
	for name, body := range accepted {
		if rec := postJSON(handler, body); rec.Code != http.StatusAccepted {
			t.Errorf("%s: expected 202, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	orch.Wait()
}

func TestMultipartRejectsEmptyPurl(t *testing.T) {
	srv, orch := newTestServer(t)
	handler := srv.Routes()
	file := func(mw *multipart.Writer) {
		fw, err := mw.CreateFormFile("content", "express.tgz")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("sample-package-bytes"))
	}

	rejected := map[string]func(*multipart.Writer){
		"empty purl next to a digest": func(mw *multipart.Writer) {
			_ = mw.WriteField("purl", "")
			_ = mw.WriteField("digest", "sha256:"+validSHA256)
		},
		"blank purl next to a digest": func(mw *multipart.Writer) {
			_ = mw.WriteField("purl", "   ")
			_ = mw.WriteField("digest", "sha256:"+validSHA256)
		},
		"empty purl next to a file": func(mw *multipart.Writer) {
			_ = mw.WriteField("purl", "")
			file(mw)
		},
		"empty purl alone": func(mw *multipart.Writer) { _ = mw.WriteField("purl", "") },
	}
	for name, build := range rejected {
		if rec := postMultipart(t, handler, "/v1/submissions", build); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: expected 422, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	// The rule must not reject good requests.
	accepted := map[string]func(*multipart.Writer){
		"digest only": func(mw *multipart.Writer) { _ = mw.WriteField("digest", "sha256:"+validSHA256) },
		"file only":   file,
	}
	for name, build := range accepted {
		if rec := postMultipart(t, handler, "/v1/submissions", build); rec.Code != http.StatusAccepted {
			t.Errorf("%s: expected 202, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	orch.Wait()
}
