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
	dbSecretFile := filepath.Join(dir, "db.secret")

	yamlContent := `
gateway:
  instanceId: "gw-file"
  listenAddr: ":9090"
storage:
  dsn: "file:from-yaml.db"
`
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("secret-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbSecretFile, []byte("postgres://user:pass@localhost:5432/scintx\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SCINTX_ADDR", ":7070")
	t.Setenv("SCINTX_AUTH_BEARER_TOKEN_FILE", secretFile)
	t.Setenv("SCINTX_DATABASE_URL_FILE", dbSecretFile)

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
	// Secret files load cleanly and override YAML.
	if cfg.Auth.BearerToken != "secret-from-file" {
		t.Fatalf("got token %q, want secret-from-file", cfg.Auth.BearerToken)
	}
	if cfg.Storage.DSN != "postgres://user:pass@localhost:5432/scintx" {
		t.Fatalf("got DSN %q, want postgres DSN", cfg.Storage.DSN)
	}
	if cfg.Revision == "" {
		t.Fatal("expected non-empty config revision")
	}
}

func TestLoadFailClosedOnUnknownFieldOrEmptySecretFile(t *testing.T) {
	dir := t.TempDir()
	badYAML := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAML, []byte("gateway:\n  unknownSetting: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badYAML); err == nil {
		t.Fatal("expected Load to fail closed on unknown YAML field")
	}

	emptySecret := filepath.Join(dir, "empty.secret")
	if err := os.WriteFile(emptySecret, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCINTX_AUTH_BEARER_TOKEN_FILE", emptySecret)
	if _, err := Load(""); err == nil {
		t.Fatal("expected Load to fail closed on empty secret file")
	}
}
