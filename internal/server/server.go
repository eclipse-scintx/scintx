// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package server implements the Eclipse SCINTX HTTP gateway endpoints.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/auth"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
)

// Server wraps the HTTP mux, configuration, store, and orchestrator.
type Server struct {
	cfg          *config.Config
	store        *gateway.Store
	orchestrator *gateway.Orchestrator
	httpServer   *http.Server
	shuttingDown atomic.Bool
}

// New creates a configured HTTP gateway Server.
func New(cfg *config.Config, store *gateway.Store, orch *gateway.Orchestrator) *Server {
	s := &Server{
		cfg:          cfg,
		store:        store,
		orchestrator: orch,
	}
	s.httpServer = &http.Server{
		Addr:              cfg.Gateway.ListenAddr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Routes returns the HTTP handler with all gateway endpoints wired.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated liveness and readiness probes.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	// Submission creation, validation, and status retrieval.
	mux.HandleFunc("POST /v1/submissions", s.handleCreateSubmission)
	mux.HandleFunc("GET /v1/submissions/{id}", s.handleGetSubmission)

	return auth.Middleware(s.cfg.Auth.BearerToken, mux)
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown marks the server as not ready, drains HTTP connections, and waits
// for in-flight submissions to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shuttingDown.Store(true)
	err := s.httpServer.Shutdown(ctx)
	s.orchestrator.Wait()
	return err
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.ProblemDetails{
		Type:   "https://scintx.example/problems/" + title,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}
