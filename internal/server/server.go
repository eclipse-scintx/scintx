// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package server exposes the SCINTX Gateway HTTP API and health probes (#41, #66, #67, #68, #69).
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/auth"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
)

// Server wraps the HTTP mux, gateway Store, Orchestrator, and lifecycle state.
type Server struct {
	cfg          *config.Config
	store        *gateway.Store
	orchestrator *gateway.Orchestrator
	httpServer   *http.Server
	rootCtx      context.Context
	rootCancel   context.CancelFunc
	shuttingDown atomic.Bool
}

// New constructs a Server for the given gateway configuration, Store, and Orchestrator.
func New(cfg *config.Config, store *gateway.Store, orch *gateway.Orchestrator) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:          cfg,
		store:        store,
		orchestrator: orch,
		rootCtx:      ctx,
		rootCancel:   cancel,
	}
}

// Routes registers all SCINTX v1 endpoints and container health probes (#41, #67, #68).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Container liveness and readiness probes (#41).
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	// Consumer and SDK submission lifecycle endpoints (#66, #67, #68, #69).
	mux.HandleFunc("POST /v1/submissions", s.handleCreateSubmission)
	mux.HandleFunc("GET /v1/submissions/{id}", s.handleGetSubmission)
	mux.HandleFunc("GET /v1/submissions/{id}/aggregate-report", s.handleGetAggregateReport)
	mux.HandleFunc("GET /v1/submissions/{id}/policy-report", s.handleGetPolicyReport)

	// Gateway metadata inspection endpoints.
	mux.HandleFunc("GET /v1/providers", s.handleListProviders)
	mux.HandleFunc("GET /v1/policies", s.handleListPolicies)

	return auth.Middleware(s.cfg.Gateway.BearerToken, mux)
}

// Start begins listening on addr with hardened HTTP server timeouts.
func (s *Server) Start(addr string) error {
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown marks readiness as false, stops accepting HTTP requests, and waits for in-flight runs.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shuttingDown.Store(true)
	var err error
	if s.httpServer != nil {
		err = s.httpServer.Shutdown(ctx)
	}
	if s.rootCancel != nil {
		s.rootCancel()
	}
	s.orchestrator.Wait()
	return err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Default().Warn("failed to encode JSON response", "err", err)
	}
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
