// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

type createSubmissionRequest struct {
	Artifact api.ArtifactInput `json:"artifact"`
}

// handleHealthz is the liveness probe.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"instanceId": s.cfg.Gateway.InstanceID,
		"version":    s.cfg.Gateway.Version,
	})
}

// handleReadyz is the readiness probe, verifying both server lifecycle state
// and persistent store connectivity (failing closed on any error).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.State() != StateReady {
		writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "gateway is not ready")
		return
	}
	if err := s.store.Ping(r.Context()); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "storage_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ready",
		"instanceId": s.cfg.Gateway.InstanceID,
	})
}

// handleCreateSubmission handles POST /v1/submissions for both JSON and
// multipart/form-data requests. It fails closed if the server is not in
// StateReady, if the Content-Type is unsupported, or if parsing/validation fails.
func (s *Server) handleCreateSubmission(w http.ResponseWriter, r *http.Request) {
	if s.State() != StateReady {
		writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "gateway is not accepting new submissions")
		return
	}

	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType := "application/json"
	if ct != "" {
		parsed, _, err := mime.ParseMediaType(ct)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "bad_request", "invalid Content-Type header")
			return
		}
		mediaType = parsed
	}

	var (
		req createSubmissionRequest
		err error
	)
	switch mediaType {
	case "multipart/form-data":
		req, err = s.parseMultipartSubmission(w, r)
	case "application/json":
		req, err = s.parseJSONSubmission(w, r)
	default:
		writeProblem(w, http.StatusBadRequest, "bad_request", "unsupported Content-Type: expected application/json or multipart/form-data")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	sub, err := s.orchestrator.Submit(r.Context(), req.Artifact)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}

	w.Header().Set("Location", "/v1/submissions/"+sub.ID)
	writeJSON(w, http.StatusAccepted, sub)
}

func (s *Server) parseJSONSubmission(w http.ResponseWriter, r *http.Request) (createSubmissionRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var req createSubmissionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return createSubmissionRequest{}, err
	}
	// Fail closed if trailing tokens exist after the first JSON object.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return createSubmissionRequest{}, errors.New("unexpected trailing data after JSON object")
	}
	return req, nil
}

func (s *Server) parseMultipartSubmission(w http.ResponseWriter, r *http.Request) (createSubmissionRequest, error) {
	maxBytes := s.cfg.Gateway.MaxContentBytes
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return createSubmissionRequest{}, err
	}
	req := createSubmissionRequest{
		Artifact: api.ArtifactInput{
			PURL:   strings.TrimSpace(r.FormValue("purl")),
			Digest: strings.TrimSpace(r.FormValue("digest")),
		},
	}
	file, header, err := r.FormFile("content")
	if err != nil && !errors.Is(err, http.ErrMissingFile) {
		return createSubmissionRequest{}, err
	}
	if err == nil {
		defer file.Close()
		data, readErr := io.ReadAll(file)
		if readErr != nil {
			return createSubmissionRequest{}, readErr
		}
		req.Artifact.Content = data
		req.Artifact.Filename = header.Filename
		req.Artifact.MediaType = header.Header.Get("Content-Type")
	}
	return req, nil
}

// handleGetSubmission handles GET /v1/submissions/{id}.
func (s *Server) handleGetSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sub, ok, err := s.store.GetSubmission(r.Context(), id)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "storage_error", err.Error())
		return
	}
	if !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "submission not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}
