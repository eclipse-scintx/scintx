// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eclipse-scintx/scintx/internal/auth"
)

func TestBearerAuthMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := auth.Middleware("secret-gateway-token", inner)

	// Health probes bypass bearer auth.
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealth := httptest.NewRecorder()
	handler.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Fatalf("got %d on /healthz, want 200", recHealth.Code)
	}

	// Missing token on /v1/submissions returns 401.
	reqUnauth := httptest.NewRequest(http.MethodGet, "/v1/submissions/123", nil)
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("got %d without token, want 401", recUnauth.Code)
	}

	// Valid token succeeds.
	reqAuth := httptest.NewRequest(http.MethodGet, "/v1/submissions/123", nil)
	reqAuth.Header.Set("Authorization", "Bearer secret-gateway-token")
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("got %d with valid token, want 200", recAuth.Code)
	}
}
