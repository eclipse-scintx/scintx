// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yeeth-security/scintx/internal/config"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := config.Default()
	if cfg.Gateway.DefaultPolicy != "baseline-security" {
		t.Fatalf("got default policy %q, want baseline-security", cfg.Gateway.DefaultPolicy)
	}
	if cfg.Revision == "" || cfg.SnapshotRef == "" {
		t.Fatal("expected computed configuration revision and snapshotRef")
	}
}

func TestConfigPrecedenceAndSecretFile(t *testing.T) {
	tmp := t.TempDir()
	secretFile := filepath.Join(tmp, "ossindex_token")
	if err := os.WriteFile(secretFile, []byte("secret-guide-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(tmp, "gateway.yaml")
	yamlContent := `schemaVersion: "1"
gateway:
  instanceId: "gw-custom"
  defaultPolicy: "baseline-security"
  policiesDir: "./policies"
  maxArtifactBytes: 1048576
providers:
  osv:
    enabled: true
    baseUrl: "https://mirror.osv.example"
    timeout: "10s"
    maxConcurrency: 5
`
	if err := os.WriteFile(cfgFile, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SCINTX_OSV_BASE_URL", "https://env.osv.example")
	t.Setenv("SCINTX_OSSINDEX_TOKEN_FILE", secretFile)

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if cfg.Gateway.InstanceID != "gw-custom" {
		t.Fatalf("got instanceId %q, want gw-custom", cfg.Gateway.InstanceID)
	}
	// Environment variable must override gateway.yaml value (#73).
	if cfg.Providers["osv"].BaseURL != "https://env.osv.example" {
		t.Fatalf("got osv baseUrl %q, want https://env.osv.example", cfg.Providers["osv"].BaseURL)
	}
	// Secret file must populate the provider token (#73).
	if cfg.Providers["ossindex"].Token != "secret-guide-token" {
		t.Fatalf("got ossindex token %q, want secret-guide-token", cfg.Providers["ossindex"].Token)
	}
}

func TestConfigValidationRejectsInvalidSettings(t *testing.T) {
	cfg := config.Default()
	bad := cfg.Providers["osv"]
	bad.Timeout = "-5s"
	cfg.Providers["osv"] = bad
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative timeout")
	}
}
