// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

const maxJSONRequestBytes = 1 << 20 // 1 MiB for JSON submission payloads

type createSubmissionJSONRequest struct {
	Artifact api.ArtifactInput `json:"artifact"`
	Policy   string            `json:"policy,omitempty"`
}

// handleHealthz is the liveness probe (#41). It returns 200 OK whenever the process is alive.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"instanceId": s.cfg.Gateway.InstanceID,
		"version":    s.cfg.Gateway.Version,
	})
}

// handleReadyz is the readiness probe (#41). It verifies the server is not shutting down,
// policies are loaded, and any required providers are available.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.shuttingDown.Load() {
		writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "gateway is shutting down")
		return
	}
	if _, err := s.orchestrator.ResolvePolicy(""); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "not_ready", err.Error())
		return
	}

	for _, adapter := range s.orchestrator.Adapters() {
		slug := adapter.Descriptor().Slug
		if pcfg, ok := s.cfg.Providers[slug]; ok && pcfg.Enabled && pcfg.Required {
			st := adapter.CheckAvailability(r.Context())
			if !st.Available {
				writeProblem(w, http.StatusServiceUnavailable, "required_provider_unavailable",
					"required provider "+slug+" is unavailable: "+strings.Join(st.Reasons, ","))
				return
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ready",
		"instanceId":    s.cfg.Gateway.InstanceID,
		"defaultPolicy": s.cfg.Gateway.DefaultPolicy,
	})
}

// handleCreateSubmission handles POST /v1/submissions for both JSON and multipart/form-data (#67, #68).
func (s *Server) handleCreateSubmission(w http.ResponseWriter, r *http.Request) {
	if s.shuttingDown.Load() {
		writeProblem(w, http.StatusServiceUnavailable, "shutting_down", "gateway is shutting down")
		return
	}

	var (
		artifact api.ArtifactInput
		policyID string
		err      error
	)
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		artifact, policyID, err = s.parseMultipartSubmission(w, r)
	} else {
		artifact, policyID, err = s.parseJSONSubmission(w, r)
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	sub, err := s.orchestrator.Submit(s.rootCtx, artifact, policyID)
	if err != nil {
		writeProblem(w, http.StatusUnprocessableEntity, "validation_failed", err.Error())
		return
	}

	w.Header().Set("Location", "/v1/submissions/"+sub.ID)
	writeJSON(w, http.StatusAccepted, sub)
}

func (s *Server) parseJSONSubmission(w http.ResponseWriter, r *http.Request) (api.ArtifactInput, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONRequestBytes)
	var req createSubmissionJSONRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		return api.ArtifactInput{}, "", err
	}
	return req.Artifact, strings.TrimSpace(req.Policy), nil
}

// parseMultipartSubmission parses Open VSX RemoteScanner multipart submissions (#67).
func (s *Server) parseMultipartSubmission(w http.ResponseWriter, r *http.Request) (api.ArtifactInput, string, error) {
	maxBytes := s.cfg.Gateway.MaxArtifactBytes + (1 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return api.ArtifactInput{}, "", err
	}

	var art api.ArtifactInput
	art.PURL = strings.TrimSpace(r.FormValue("purl"))
	art.MediaType = strings.TrimSpace(r.FormValue("mediaType"))
	policyID := strings.TrimSpace(r.FormValue("policy"))

	file, header, err := r.FormFile("content")
	if err == nil {
		defer file.Close()
		data, readErr := io.ReadAll(file)
		if readErr != nil {
			return api.ArtifactInput{}, "", readErr
		}
		art.Content = data
		if header != nil && header.Filename != "" {
			art.Filename = header.Filename
		}
		if art.MediaType == "" {
			art.MediaType = "application/octet-stream"
		}
	}
	return art, policyID, nil
}

// handleGetSubmission handles GET /v1/submissions/{id} (#66, #67, #75).
func (s *Server) handleGetSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sub, ok := s.store.GetSubmission(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "submission not found")
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

// handleGetAggregateReport handles GET /v1/submissions/{id}/aggregate-report (#68).
func (s *Server) handleGetAggregateReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.GetSubmission(id); !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "submission not found")
		return
	}
	agg, ok := s.store.GetAggregateReportBySubmission(id)
	if !ok {
		writeProblem(w, http.StatusConflict, "report_not_ready", "aggregate report is not ready yet")
		return
	}
	writeJSON(w, http.StatusOK, agg)
}

// handleGetPolicyReport handles GET /v1/submissions/{id}/policy-report (#67, #68).
func (s *Server) handleGetPolicyReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.store.GetSubmission(id); !ok {
		writeProblem(w, http.StatusNotFound, "not_found", "submission not found")
		return
	}
	polRep, ok := s.store.GetPolicyReportBySubmission(id)
	if !ok {
		writeProblem(w, http.StatusConflict, "report_not_ready", "policy report is not ready yet")
		return
	}
	writeJSON(w, http.StatusOK, polRep)
}

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	type providerInfo struct {
		Descriptor   api.AdapterDescriptor  `json:"descriptor"`
		Availability api.AvailabilityStatus `json:"availability"`
	}
	adapters := s.orchestrator.Adapters()
	out := make([]providerInfo, 0, len(adapters))
	for _, a := range adapters {
		out = append(out, providerInfo{
			Descriptor:   a.Descriptor(),
			Availability: a.CheckAvailability(r.Context()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	pols := s.orchestrator.Policies()
	out := make([]*api.PolicyDefinition, 0, len(pols))
	for _, p := range pols {
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": out})
}
