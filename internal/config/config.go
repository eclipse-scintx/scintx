// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package config loads and validates Eclipse SCINTX gateway configuration and
// credential overrides.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/yeeth-security/scintx/api"
	"gopkg.in/yaml.v3"
)

// Config holds the complete gateway configuration.
type Config struct {
	Gateway GatewaySettings `yaml:"gateway" json:"gateway"`
	Storage StorageSettings `yaml:"storage" json:"storage"`
	Auth    AuthSettings    `yaml:"auth" json:"auth"`

	// Revision is a short SHA-256 fingerprint of the resolved configuration.
	Revision string `yaml:"-" json:"-"`
}

// GatewaySettings configures HTTP server and submission limits.
type GatewaySettings struct {
	InstanceID      string `yaml:"instanceId" json:"instanceId"`
	Version         string `yaml:"version" json:"version"`
	ListenAddr      string `yaml:"listenAddr" json:"listenAddr"`
	MaxContentBytes int64  `yaml:"maxContentBytes" json:"maxContentBytes"`
}

// StorageSettings configures persistent submission storage (SQLite or PostgreSQL).
type StorageSettings struct {
	// DSN is a SQLite path/URI (e.g. "file:data/scintx.db") or a PostgreSQL
	// connection URI ("postgres://..."). Use "memory" for in-memory storage.
	DSN string `yaml:"dsn" json:"dsn"`
}

// AuthSettings configures optional inbound authentication for /v1/* endpoints.
type AuthSettings struct {
	BearerToken string `yaml:"-" json:"-"`
}

// Default returns the built-in default gateway configuration.
func Default() *Config {
	return &Config{
		Gateway: GatewaySettings{
			InstanceID:      "gateway-001",
			Version:         "0.1.0",
			ListenAddr:      ":8080",
			MaxContentBytes: api.DefaultMaxContentBytes,
		},
		Storage: StorageSettings{
			DSN: "file:data/scintx.db",
		},
	}
}

// Load reads configuration from an optional YAML file and applies environment
// variable and secret file overrides in precedence order:
//  1. Environment variables / *_FILE secret files (highest precedence)
//  2. Gateway configuration file (gateway.yaml)
//  3. Built-in defaults (lowest precedence)
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config file %q: %w", path, err)
		}
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	raw, _ := yaml.Marshal(cfg)
	sum := sha256.Sum256(raw)
	cfg.Revision = hex.EncodeToString(sum[:6])
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) error {
	if v := strings.TrimSpace(os.Getenv("SCINTX_ADDR")); v != "" {
		cfg.Gateway.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("SCINTX_INSTANCE_ID")); v != "" {
		cfg.Gateway.InstanceID = v
	}

	dbDSN, err := resolveSecret("SCINTX_DATABASE_URL")
	if err != nil {
		return err
	}
	if dbDSN != "" {
		cfg.Storage.DSN = dbDSN
	}

	bearer, err := resolveSecret("SCINTX_AUTH_BEARER_TOKEN")
	if err != nil {
		return err
	}
	if bearer != "" {
		cfg.Auth.BearerToken = bearer
	}
	return nil
}

// resolveSecret reads <ENV_NAME>_FILE if set, or falls back to <ENV_NAME>.
func resolveSecret(envName string) (string, error) {
	fileEnv := envName + "_FILE"
	if filePath := strings.TrimSpace(os.Getenv(fileEnv)); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read secret file %s=%q: %w", fileEnv, filePath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return strings.TrimSpace(os.Getenv(envName)), nil
}

// Validate checks structural configuration rules at startup.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Gateway.ListenAddr) == "" {
		return fmt.Errorf("gateway.listenAddr is required")
	}
	if c.Gateway.MaxContentBytes <= 0 {
		return fmt.Errorf("gateway.maxContentBytes must be positive")
	}
	if strings.TrimSpace(c.Storage.DSN) == "" {
		return fmt.Errorf("storage.dsn is required")
	}
	return nil
}
