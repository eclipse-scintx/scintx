// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrecedenceAndValidation(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "gateway.yaml")
	secretFile := filepath.Join(dir, "bearer.secret")

	yamlContent := `
gateway:
  instanceId: "gw-file"
  listenAddr: ":9090"
`
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("secret-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SCINTX_ADDR", ":7070")
	t.Setenv("SCINTX_AUTH_BEARER_TOKEN_FILE", secretFile)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Env override wins over file.
	if cfg.Gateway.ListenAddr != ":7070" {
		t.Fatalf("got ListenAddr %q, want :7070", cfg.Gateway.ListenAddr)
	}
	// File value wins over built-in default.
	if cfg.Gateway.InstanceID != "gw-file" {
		t.Fatalf("got InstanceID %q, want gw-file", cfg.Gateway.InstanceID)
	}
	// Secret file loads cleanly.
	if cfg.Auth.BearerToken != "secret-from-file" {
		t.Fatalf("got token %q, want secret-from-file", cfg.Auth.BearerToken)
	}
	if cfg.Revision == "" {
		t.Fatal("expected non-empty config revision")
	}
}
