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

	// Wrong token (both shorter and same length) returns 401.
	for _, bad := range []string{"short", "secret-gateway-tokeX"} {
		reqBad := httptest.NewRequest(http.MethodGet, "/v1/submissions/123", nil)
		reqBad.Header.Set("Authorization", "Bearer "+bad)
		recBad := httptest.NewRecorder()
		handler.ServeHTTP(recBad, reqBad)
		if recBad.Code != http.StatusUnauthorized {
			t.Fatalf("got %d with invalid token %q, want 401", recBad.Code, bad)
		}
	}

	// The scheme name is case-insensitive, so other letter cases also work.
	for _, scheme := range []string{"bearer", "BEARER", "BeArEr"} {
		reqCase := httptest.NewRequest(http.MethodGet, "/v1/submissions/123", nil)
		reqCase.Header.Set("Authorization", scheme+" secret-gateway-token")
		recCase := httptest.NewRecorder()
		handler.ServeHTTP(recCase, reqCase)
		if recCase.Code != http.StatusOK {
			t.Fatalf("got %d with scheme %q, want 200", recCase.Code, scheme)
		}
	}

	// A different scheme, or a scheme with no token, is still refused.
	for _, hdr := range []string{"Basic secret-gateway-token", "Bearer", "Bearertoken secret-gateway-token"} {
		reqScheme := httptest.NewRequest(http.MethodGet, "/v1/submissions/123", nil)
		reqScheme.Header.Set("Authorization", hdr)
		recScheme := httptest.NewRecorder()
		handler.ServeHTTP(recScheme, reqScheme)
		if recScheme.Code != http.StatusUnauthorized {
			t.Fatalf("got %d with header %q, want 401", recScheme.Code, hdr)
		}
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
