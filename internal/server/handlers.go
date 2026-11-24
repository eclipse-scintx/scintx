// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"encoding/json"
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

// handleReadyz is the readiness probe.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s.shuttingDown.Load() {
		writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "gateway is shutting down")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ready",
		"instanceId": s.cfg.Gateway.InstanceID,
	})
}

// handleCreateSubmission handles POST /v1/submissions for both JSON and
// multipart/form-data requests.
func (s *Server) handleCreateSubmission(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)

	var (
		req createSubmissionRequest
		err error
	)
	switch {
	case strings.HasPrefix(mediaType, "multipart/form-data"):
		req, err = s.parseMultipartSubmission(r)
	default:
		req, err = s.parseJSONSubmission(r)
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

func (s *Server) parseJSONSubmission(r *http.Request) (createSubmissionRequest, error) {
	defer r.Body.Close()
	var req createSubmissionRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return createSubmissionRequest{}, err
	}
	return req, nil
}

func (s *Server) parseMultipartSubmission(r *http.Request) (createSubmissionRequest, error) {
	maxBytes := s.cfg.Gateway.MaxContentBytes
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes+(1<<20))
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
	sub, ok := s.store.GetSubmission(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "submission not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}
