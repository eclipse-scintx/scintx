// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package auth provides optional Bearer token authentication for consumer requests
// to the Eclipse SCINTX Gateway, matching the Open VSX RemoteScanner bearer configuration.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/eclipse-scintx/scintx/api"
)

// Middleware enforces Bearer token authentication on /v1/* routes when expectedToken is non-empty.
// Health probes (/healthz and /readyz) remain unauthenticated so container orchestrators can probe them.
func Middleware(expectedToken string, next http.Handler) http.Handler {
	token := strings.TrimSpace(expectedToken)
	if token == "" {
		return next
	}
	// Hash the expected token once with SHA-256. subtle.ConstantTimeCompare
	// returns immediately when two byte slices have different lengths, which
	// can leak the secret token's length through timing. Comparing two fixed
	// 32-byte SHA-256 digests always runs in constant time for any input length.
	expectedHash := sha256.Sum256([]byte(token))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		hdr := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(hdr, prefix) {
			writeUnauthorized(w, "missing Bearer token in Authorization header")
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(hdr, prefix))
		providedHash := sha256.Sum256([]byte(provided))
		if subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) != 1 {
			writeUnauthorized(w, "invalid Bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeUnauthorized(w http.ResponseWriter, detail string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="scintx"`)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(api.ProblemDetails{
		Type:   "https://scintx.example/problems/unauthorized",
		Title:  "unauthorized",
		Status: http.StatusUnauthorized,
		Detail: detail,
	})
}
