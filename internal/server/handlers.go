// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/eclipse-scintx/scintx/api"
	"github.com/eclipse-scintx/scintx/internal/blob"
)

type createSubmissionRequest struct {
	Artifact api.ArtifactInput `json:"artifact"`
	// content is the staged file of a multipart upload. It is nil for JSON
	// requests. It is unexported, so a JSON body can never set it.
	content blob.Upload
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
		// This endpoint needs no login, and a database error can name the
		// host, user, and database. So the detail goes to the log only and
		// the caller gets a fixed message.
		slog.Warn("readiness check failed: storage ping error", "error", err)
		writeProblem(w, http.StatusServiceUnavailable, "storage_unavailable", "storage is not reachable")
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
		// An oversized upload is found while the body streams by. It is a
		// validation failure (422), the same as before streaming was added.
		if errors.Is(err, api.ErrValidation) {
			writeProblem(w, http.StatusUnprocessableEntity, "validation_failed", err.Error())
			return
		}
		// The upload could not be written to blob storage (a full disk, for
		// example). That is our fault, not the client's, so it is a 500. The
		// real error can name file paths, so it goes to the log only.
		if errors.Is(err, blob.ErrStorage) {
			slog.Error("store uploaded content failed", "error", err)
			writeProblem(w, http.StatusInternalServerError, "storage_error", "the upload could not be stored")
			return
		}
		writeProblem(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// SubmitWithContent takes over the staged upload (nil for JSON requests).
	// It keeps the bytes on success and deletes them on every error.
	sub, err := s.orchestrator.SubmitWithContent(r.Context(), req.Artifact, req.content)
	if err != nil {
		if errors.Is(err, api.ErrValidation) {
			writeProblem(w, http.StatusUnprocessableEntity, "validation_failed", err.Error())
			return
		}
		// Raw storage errors can leak database details. Log the real error
		// and send the caller a fixed message.
		slog.Error("store new submission failed", "error", err)
		writeProblem(w, http.StatusInternalServerError, "storage_error", "the submission could not be stored")
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

// handleGetSubmission handles GET /v1/submissions/{id}.
// It validates the submission ID format before querying storage (fail-closed).
func (s *Server) handleGetSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !api.IsValidSubmissionID(id) {
		writeProblem(w, http.StatusBadRequest, "bad_request", "invalid submission id format")
		return
	}
	sub, ok, err := s.store.GetSubmission(r.Context(), id)
	if err != nil {
		// Same rule as above: real error to the log, fixed message to the caller.
		slog.Error("read submission failed", "id", id, "error", err)
		writeProblem(w, http.StatusInternalServerError, "storage_error", "the submission could not be read")
		return
	}
	if !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "submission not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}
