// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package config loads and validates SCINTX gateway and provider adapter settings.
// It implements the precedence and secret-handling rules defined in issue #73:
//  1. Environment variables and mounted *_FILE secrets (highest precedence)
//  2. Gateway configuration file (gateway.yaml)
//  3. Built-in defaults (lowest precedence)
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
	"gopkg.in/yaml.v3"
)

// DefaultMaxArtifactBytes caps uploaded artifact content at 100 MiB by default.
const DefaultMaxArtifactBytes int64 = 100 << 20

// Config holds the resolved gateway and provider adapter configuration (#73).
type Config struct {
	SchemaVersion string                      `yaml:"schemaVersion" json:"schemaVersion"`
	Gateway       GatewaySettings             `yaml:"gateway" json:"gateway"`
	Providers     map[string]ProviderSettings `yaml:"providers" json:"providers"`

	// Revision is the immutable SHA-256 digest of the resolved non-secret settings.
	Revision string `yaml:"-" json:"-"`

	// SnapshotRef identifies the configuration snapshot in Aggregate Reports (#68).
	SnapshotRef string `yaml:"-" json:"-"`
}

// GatewaySettings holds global gateway server and policy settings (#73).
type GatewaySettings struct {
	InstanceID       string `yaml:"instanceId" json:"instanceId"`
	Version          string `yaml:"version" json:"version"`
	Addr             string `yaml:"addr" json:"addr"`
	DefaultPolicy    string `yaml:"defaultPolicy" json:"defaultPolicy"`
	PoliciesDir      string `yaml:"policiesDir" json:"policiesDir"`
	MaxArtifactBytes int64  `yaml:"maxArtifactBytes" json:"maxArtifactBytes"`
	BearerToken      string `yaml:"-" json:"-"`
}

// ProviderSettings holds per-adapter operational and credential settings (#73).
type ProviderSettings struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	Required       bool          `yaml:"required" json:"required"`
	BaseURL        string        `yaml:"baseUrl" json:"baseUrl"`
	Timeout        string        `yaml:"timeout" json:"timeout"`
	MaxConcurrency int           `yaml:"maxConcurrency" json:"maxConcurrency"`
	RequireAuth    bool          `yaml:"requireAuth,omitempty" json:"requireAuth,omitempty"`
	Username       string        `yaml:"-" json:"-"`
	Token          string        `yaml:"-" json:"-"`
	ParsedTimeout  time.Duration `yaml:"-" json:"-"`
}

// Default returns the built-in gateway configuration so SCINTX works out of the box (#65, #73).
func Default() *Config {
	cfg := &Config{
		SchemaVersion: api.SchemaVersionV1,
		Gateway: GatewaySettings{
			InstanceID:       "gateway-001",
			Version:          "0.1.0",
			Addr:             ":8080",
			DefaultPolicy:    "baseline-security",
			PoliciesDir:      "./policies",
			MaxArtifactBytes: DefaultMaxArtifactBytes,
		},
		Providers: map[string]ProviderSettings{
			"osv": {
				Enabled:        true,
				Required:       false,
				BaseURL:        "https://api.osv.dev",
				Timeout:        "15s",
				MaxConcurrency: 20,
			},
			"ossindex": {
				Enabled:        true,
				Required:       false,
				BaseURL:        "https://ossindex.sonatype.org",
				Timeout:        "30s",
				MaxConcurrency: 10,
				RequireAuth:    true,
			},
		},
	}
	_ = cfg.Validate()
	return cfg
}

// Load reads gateway configuration from path (if non-empty and present),
// applies environment variable and secret-file overrides, and validates all settings (#73).
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		path = strings.TrimSpace(os.Getenv("SCINTX_CONFIG"))
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read gateway config %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse gateway config %q: %w", path, err)
		}
	} else if data, err := os.ReadFile("gateway.yaml"); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse default gateway.yaml: %w", err)
		}
	}

	applyEnvOverrides(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnvOverrides applies environment variables and *_FILE secret mounts (#73).
func applyEnvOverrides(cfg *Config) {
	if v := strings.TrimSpace(os.Getenv("SCINTX_ADDR")); v != "" {
		cfg.Gateway.Addr = v
	}
	if v := strings.TrimSpace(os.Getenv("SCINTX_INSTANCE_ID")); v != "" {
		cfg.Gateway.InstanceID = v
	}
	if v := strings.TrimSpace(os.Getenv("SCINTX_DEFAULT_POLICY")); v != "" {
		cfg.Gateway.DefaultPolicy = v
	}
	if v := strings.TrimSpace(os.Getenv("SCINTX_POLICIES_DIR")); v != "" {
		cfg.Gateway.PoliciesDir = v
	}
	cfg.Gateway.BearerToken = resolveSecret("SCINTX_AUTH_BEARER_TOKEN", "SCINTX_TOKEN")

	osvCfg := cfg.Providers["osv"]
	if v := strings.TrimSpace(os.Getenv("SCINTX_OSV_BASE_URL")); v != "" {
		osvCfg.BaseURL = v
	}
	if tok := resolveSecret("SCINTX_OSV_BEARER_TOKEN"); tok != "" {
		osvCfg.Token = tok
	}
	cfg.Providers["osv"] = osvCfg

	ossCfg := cfg.Providers["ossindex"]
	if v := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_BASE_URL")); v != "" {
		ossCfg.BaseURL = v
	}
	if u := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_USERNAME")); u != "" {
		ossCfg.Username = u
	} else if u := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_USER")); u != "" {
		ossCfg.Username = u
	}
	if tok := resolveSecret("SCINTX_OSSINDEX_TOKEN"); tok != "" {
		ossCfg.Token = tok
	}
	cfg.Providers["ossindex"] = ossCfg
}

// resolveSecret reads a secret from <KEY>_FILE first, then <KEY> (#73).
func resolveSecret(keys ...string) string {
	for _, key := range keys {
		if filePath := strings.TrimSpace(os.Getenv(key + "_FILE")); filePath != "" {
			if data, err := os.ReadFile(filePath); err == nil {
				return strings.TrimSpace(string(data))
			}
		}
		if val := strings.TrimSpace(os.Getenv(key)); val != "" {
			return val
		}
	}
	return ""
}

// Validate checks configuration values and computes the immutable Revision digest (#73).
func (c *Config) Validate() error {
	if c.SchemaVersion == "" {
		c.SchemaVersion = api.SchemaVersionV1
	}
	if c.SchemaVersion != api.SchemaVersionV1 {
		return fmt.Errorf("unsupported gateway config schemaVersion %q", c.SchemaVersion)
	}
	if strings.TrimSpace(c.Gateway.DefaultPolicy) == "" {
		return fmt.Errorf("gateway.defaultPolicy must not be empty")
	}
	if c.Gateway.MaxArtifactBytes <= 0 {
		return fmt.Errorf("gateway.maxArtifactBytes must be positive")
	}
	for slug, p := range c.Providers {
		if p.Timeout == "" {
			p.Timeout = "30s"
		}
		d, err := time.ParseDuration(p.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("provider %q has invalid timeout %q", slug, p.Timeout)
		}
		p.ParsedTimeout = d
		if p.MaxConcurrency <= 0 {
			return fmt.Errorf("provider %q maxConcurrency must be positive", slug)
		}
		u, err := url.Parse(p.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("provider %q has invalid baseUrl %q", slug, p.BaseURL)
		}
		c.Providers[slug] = p
	}
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	c.Revision = hex.EncodeToString(sum[:6])
	c.SnapshotRef = "config-snapshot-" + c.Revision
	return nil
}
