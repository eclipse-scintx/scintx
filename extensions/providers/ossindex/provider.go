// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package ossindex implements the SCINTX ProviderAdapter for Sonatype OSS Index
// and the Sonatype Guide OSS Index Compatibility API (#43, #70, #73, #74).
package ossindex

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

const defaultBaseURL = "https://ossindex.sonatype.org"

var supportedPURLTypes = []string{
	"npm", "pypi", "maven", "golang", "cargo", "gem",
	"nuget", "composer", "cocoapods", "conan", "cran", "rpm", "swift",
}

// Config holds endpoint and authentication settings for the OSS Index adapter (#73).
type Config struct {
	BaseURL  string
	Username string
	Token    string
}

// Adapter implements api.ProviderAdapter for Sonatype OSS Index.
type Adapter struct {
	cfg        Config
	httpClient *http.Client
}

func init() {
	api.RegisterAdapterFactory("ossindex", func() (api.ProviderAdapter, error) {
		return NewAdapterFromEnv(), nil
	})
}

// NewAdapterFromEnv constructs an OSS Index Adapter from environment variables (#73).
func NewAdapterFromEnv() *Adapter {
	token := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_TOKEN"))
	if tokenFile := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_TOKEN_FILE")); tokenFile != "" {
		if data, err := os.ReadFile(tokenFile); err == nil {
			token = strings.TrimSpace(string(data))
		}
	}
	user := strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_USERNAME"))
	if user == "" {
		user = strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_USER"))
	}
	return NewAdapter(Config{
		BaseURL:  strings.TrimSpace(os.Getenv("SCINTX_OSSINDEX_BASE_URL")),
		Username: user,
		Token:    token,
	}, nil)
}

// NewAdapter creates an OSS Index Adapter with explicit configuration and HTTP client.
func NewAdapter(cfg Config, httpClient *http.Client) *Adapter {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Adapter{cfg: cfg, httpClient: httpClient}
}

// Descriptor declares the OSS Index adapter identity, supported PURL types, and capabilities (#70, #71).
func (a *Adapter) Descriptor() api.AdapterDescriptor {
	return api.AdapterDescriptor{
		Slug:                   "ossindex",
		AdapterVersion:         "1.0.0",
		SupportedSchemaVersion: api.SchemaVersionV1,
		SupportedInputs: api.SupportedInputs{
			Types:      []api.ArtifactInputType{api.InputTypePURL},
			Ecosystems: supportedPURLTypes,
		},
		Capabilities: []api.Capability{
			api.CapabilityVulnerabilities,
		},
	}
}

// CheckAvailability checks that OSS Index URL and required credentials are configured (#70, #73).
// When SCINTX_OSSINDEX_TOKEN is unset, it returns StateUnconfigured and "missing_credentials"
// so the gateway records why OSS Index was not executed in the Aggregate Report (#68, #73).
func (a *Adapter) CheckAvailability(ctx context.Context) api.AvailabilityStatus {
	now := time.Now().UTC()
	u, err := url.Parse(a.cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return api.AvailabilityStatus{
			State:     api.StateUnconfigured,
			Available: false,
			Reasons:   []string{"invalid_configuration"},
			Message:   fmt.Sprintf("invalid OSS Index base URL %q", a.cfg.BaseURL),
			CheckedAt: now,
		}
	}
	if strings.TrimSpace(a.cfg.Token) == "" {
		return api.AvailabilityStatus{
			State:     api.StateUnconfigured,
			Available: false,
			Reasons:   []string{"missing_credentials"},
			Message:   "SCINTX_OSSINDEX_TOKEN is required for Sonatype OSS Index",
			CheckedAt: now,
		}
	}
	return api.AvailabilityStatus{
		State:     api.StateReady,
		Available: true,
		CheckedAt: now,
	}
}
