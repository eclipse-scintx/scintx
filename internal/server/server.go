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

// LifecycleState represents the explicit state machine of the HTTP gateway server:
//
//	StateReady -> StateDraining -> StateStopped
type LifecycleState int32

const (
	StateReady    LifecycleState = 1
	StateDraining LifecycleState = 2
	StateStopped  LifecycleState = 3
)

// Server wraps the HTTP mux, configuration, store, orchestrator, and server
// lifecycle state machine.
type Server struct {
	cfg          *config.Config
	store        gateway.Store
	orchestrator *gateway.Orchestrator
	httpServer   *http.Server
	state        atomic.Int32
}

// New creates a configured HTTP gateway Server in StateReady.
func New(cfg *config.Config, store gateway.Store, orch *gateway.Orchestrator) *Server {
	s := &Server{
		cfg:          cfg,
		store:        store,
		orchestrator: orch,
	}
	s.state.Store(int32(StateReady))
	s.httpServer = &http.Server{
		Addr:              cfg.Gateway.ListenAddr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// State returns the current server lifecycle state.
func (s *Server) State() LifecycleState {
	return LifecycleState(s.state.Load())
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

// Shutdown transitions the server from StateReady to StateDraining, drains
// HTTP connections, waits for in-flight submissions to finish, closes the
// persistent store, and transitions to StateStopped.
func (s *Server) Shutdown(ctx context.Context) error {
	s.state.Store(int32(StateDraining))
	err := s.httpServer.Shutdown(ctx)
	s.orchestrator.Wait()
	_ = s.store.Close()
	s.state.Store(int32(StateStopped))
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
