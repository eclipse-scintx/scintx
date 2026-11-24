// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package auth provides optional Bearer token authentication for consumer requests
// to the Eclipse SCINTX Gateway, matching the Open VSX RemoteScanner bearer configuration.
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// Middleware enforces Bearer token authentication on /v1/* routes when expectedToken is non-empty.
// Health probes (/healthz and /readyz) remain unauthenticated so container orchestrators can probe them.
func Middleware(expectedToken string, next http.Handler) http.Handler {
	token := strings.TrimSpace(expectedToken)
	if token == "" {
		return next
	}

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
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
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
