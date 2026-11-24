// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
)

// This file parses multipart/form-data submissions. It was split out of
// handlers.go to keep each file small.

// maxTextFieldBytes caps the "purl" and "digest" text fields. The longest
// valid value is a purl of api.MaxPurlLength (2048) bytes, so 4096 is plenty.
const maxTextFieldBytes = 4096

// parseMultipartSubmission reads a multipart/form-data submission as a stream.
//
// It replaces r.ParseMultipartForm, r.FormValue, and io.ReadAll. That older
// approach had three problems:
//
//  1. r.FormValue also reads the URL query string. So "?purl=..." overrode
//     the body field and skipped the unknown-field check.
//  2. A repeated "purl" field was accepted and the first value silently won.
//  3. The whole upload was copied into memory (up to 64 MiB per request).
//
// Reading the parts one by one fixes all three. Only the request body is
// read, each field may appear once, and the file is hashed as it streams by.
//
// The file is also written to blob storage as it streams by, so a provider
// adapter can read it later. (Before blob storage existed, the bytes were
// only hashed and then dropped.) The file is still never held in memory:
// each upload uses one small copy buffer, however large the file is. That
// keeps memory flat when many uploads arrive at once.
func (s *Server) parseMultipartSubmission(w http.ResponseWriter, r *http.Request) (createSubmissionRequest, error) {
	maxBytes := s.cfg.Gateway.MaxContentBytes
	// Hard cap on the whole body: the file limit plus 1 MiB for the framing.
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		return createSubmissionRequest{}, err
	}

	// staged is the upload being written to blob storage. Unless parsing
	// succeeds, the deferred Discard deletes it. This covers every error
	// return below, such as an oversized file or a client that disconnects.
	var staged blob.Upload
	parsed := false
	defer func() {
		if !parsed && staged != nil {
			staged.Discard()
		}
	}()

	var req createSubmissionRequest
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			// Hand the staged upload to the caller, who now owns it.
			parsed = true
			req.content = staged
			return req, nil
		}
		if err != nil {
			return createSubmissionRequest{}, err
		}
		name := part.FormName()
		// Fail closed on a repeated field instead of guessing which one wins.
		if seen[name] {
			return createSubmissionRequest{}, fmt.Errorf("duplicate multipart field %q", name)
		}
		seen[name] = true

		isFile := part.FileName() != ""
		switch {
		case name == "purl" && !isFile:
			req.Artifact.PURL, err = readTextField(part, name)
		case name == "digest" && !isFile:
			var rawDigest string
			rawDigest, err = readTextField(part, name)
			if err == nil {
				// Convert the "<algorithm>:<hex>" text field into the structured
				// Digest model (#68, #70). Validation runs next in SubmitWithContent.
				req.Artifact.Digest = api.ParseDigest(rawDigest)
			}
		case name == "content" && isFile:
			// The staging file is created only here. A request without a
			// file never touches the disk. The duplicate check above makes
			// sure this runs at most once per request.
			staged, err = s.orchestrator.NewUpload()
			if err == nil {
				req.Artifact.Upload, err = storeUploadPart(part, maxBytes, staged)
			}
		default:
			// Fail closed on any unknown form field or file part name.
			err = fmt.Errorf("unknown multipart field %q", name)
		}
		if err != nil {
			return createSubmissionRequest{}, err
		}
	}
}

// readTextField reads one small text field and rejects an oversized value.
// It reads one byte past the cap so it can tell "exactly at the cap" from
// "too long" without reading an unbounded amount.
func readTextField(part *multipart.Part, name string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(part, maxTextFieldBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxTextFieldBytes {
		return "", fmt.Errorf("multipart field %q exceeds %d bytes", name, maxTextFieldBytes)
	}
	return string(data), nil
}

// storeUploadPart streams the uploaded file through SHA-256 and returns what
// was measured. The filename and media type are still untrusted here. They
// are checked later by api.ValidateAndNormalizeArtifact.
//
// It was called hashUploadPart before blob storage was added. It now also
// writes the file to staged. The TeeReader does this: every chunk that the
// hash reads from the request is written to staged first. So the hash and
// the stored bytes always match, and the file is read only once.
//
// HashContent stops reading at maxBytes+1, so an oversized upload can never
// write more than that to disk.
func storeUploadPart(part *multipart.Part, maxBytes int64, staged io.Writer) (*api.ContentMetadata, error) {
	sum, size, err := api.HashContent(io.TeeReader(part, staged), maxBytes)
	if err != nil {
		return nil, err
	}
	return &api.ContentMetadata{
		SHA256:    sum,
		SizeBytes: size,
		Filename:  part.FileName(),
		MediaType: part.Header.Get("Content-Type"),
	}, nil
}
