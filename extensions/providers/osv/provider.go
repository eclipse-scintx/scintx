// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package osv implements the SCINTX ProviderAdapter for OSV.dev (#70, #71, #74).
// It queries POST /v1/query by PURL, falls back to "VSCode:https://open-vsx.org"
// for Open VSX extensions, and maps advisories into vulnerabilities and threats.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
)

const defaultBaseURL = "https://api.osv.dev"

var supportedPURLTypes = []string{
	"npm", "pypi", "maven", "golang", "cargo", "gem",
	"nuget", "composer", "hex", "pub", "swift", "cran",
	"bioconductor", "hackage", "conan", "debian", "alpine",
	"ubuntu", "rocky", "almalinux", "vscode-extension",
}

// Config holds endpoint and optional authentication settings for the OSV adapter (#70, #73).
type Config struct {
	BaseURL     string
	RequireAuth bool
	BearerToken string
	OfflineDemo bool
}

// Adapter implements api.ProviderAdapter for the OSV.dev HTTP API.
type Adapter struct {
	cfg        Config
	httpClient *http.Client
}

func init() {
	api.RegisterAdapterFactory("osv", func() (api.ProviderAdapter, error) {
		return NewAdapterFromEnv(), nil
	})
}

// NewAdapterFromEnv constructs an OSV Adapter using environment variables (#73).
func NewAdapterFromEnv() *Adapter {
	return NewAdapter(Config{
		BaseURL:     strings.TrimSpace(os.Getenv("SCINTX_OSV_BASE_URL")),
		BearerToken: strings.TrimSpace(os.Getenv("SCINTX_OSV_BEARER_TOKEN")),
		OfflineDemo: strings.TrimSpace(os.Getenv("SCINTX_DEMO_FIXTURES")) == "1",
	}, nil)
}

// NewAdapter creates an OSV Adapter with explicit configuration and HTTP client.
func NewAdapter(cfg Config, httpClient *http.Client) *Adapter {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Adapter{cfg: cfg, httpClient: httpClient}
}

// Descriptor declares the OSV adapter identity, supported PURL ecosystems, and capabilities (#70, #71).
func (a *Adapter) Descriptor() api.AdapterDescriptor {
	return api.AdapterDescriptor{
		Slug:                   "osv",
		AdapterVersion:         "1.0.0",
		SupportedSchemaVersion: api.SchemaVersionV1,
		SupportedInputs: api.SupportedInputs{
			Types:      []api.ArtifactInputType{api.InputTypePURL},
			Ecosystems: supportedPURLTypes,
		},
		Capabilities: []api.Capability{
			api.CapabilityVulnerabilities,
			api.CapabilityThreats,
		},
	}
}

// CheckAvailability validates the adapter's configuration, credentials, and readiness (#70, #73, #74).
func (a *Adapter) CheckAvailability(ctx context.Context) api.AvailabilityStatus {
	now := time.Now().UTC()
	u, err := url.Parse(a.cfg.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return api.AvailabilityStatus{
			State:     api.StateUnconfigured,
			Available: false,
			Reasons:   []string{"invalid_configuration"},
			Message:   fmt.Sprintf("invalid OSV base URL %q", a.cfg.BaseURL),
			CheckedAt: now,
		}
	}
	if a.cfg.RequireAuth && strings.TrimSpace(a.cfg.BearerToken) == "" {
		return api.AvailabilityStatus{
			State:     api.StateUnconfigured,
			Available: false,
			Reasons:   []string{"missing_credentials"},
			Message:   "OSV mirror requires a bearer token, but none is configured",
			CheckedAt: now,
		}
	}
	if a.cfg.OfflineDemo || a.cfg.BaseURL == defaultBaseURL {
		return api.AvailabilityStatus{
			State:     api.StateReady,
			Available: true,
			CheckedAt: now,
		}
	}
	return a.probeEndpoint(ctx, now)
}

func (a *Adapter) probeEndpoint(ctx context.Context, now time.Time) api.AvailabilityStatus {
	probeBody := []byte(`{"package":{"purl":"pkg:npm/lodash@4.17.21"}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.BaseURL+"/v1/query", bytes.NewReader(probeBody))
	if err != nil {
		return api.AvailabilityStatus{
			State:     api.StateUnconfigured,
			Available: false,
			Reasons:   []string{"invalid_configuration"},
			Message:   err.Error(),
			CheckedAt: now,
		}
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.BearerToken)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return api.AvailabilityStatus{
			State:     api.StateUnreachable,
			Available: false,
			Reasons:   []string{"upstream_unreachable"},
			Message:   err.Error(),
			CheckedAt: now,
		}
	}
	_ = resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return api.AvailabilityStatus{
			State:     api.StateUnreachable,
			Available: false,
			Reasons:   []string{"authentication_failed"},
			Message:   fmt.Sprintf("OSV rejected credentials with HTTP %d", resp.StatusCode),
			CheckedAt: now,
		}
	case resp.StatusCode == http.StatusTooManyRequests:
		return api.AvailabilityStatus{
			State:     api.StateDegraded,
			Available: true,
			Reasons:   []string{"rate_limited"},
			Message:   "OSV API is currently rate-limited",
			CheckedAt: now,
		}
	case resp.StatusCode != http.StatusOK:
		return api.AvailabilityStatus{
			State:     api.StateUnreachable,
			Available: false,
			Reasons:   []string{"upstream_unreachable"},
			Message:   fmt.Sprintf("OSV returned HTTP %d", resp.StatusCode),
			CheckedAt: now,
		}
	default:
		return api.AvailabilityStatus{State: api.StateReady, Available: true, CheckedAt: now}
	}
}

// Evaluate queries OSV and normalizes advisories into a ProviderReport (#70, #72).
func (a *Adapter) Evaluate(ctx context.Context, req api.EvaluationRequest) (*api.EvaluationResult, error) {
	if req.Artifact.PURL == "" {
		return nil, &api.AdapterError{
			Code:      api.ErrUnsupportedInput,
			Message:   "osv adapter requires a package PURL",
			Retryable: false,
		}
	}
	if _, hasVer, err := api.PurlVersion(req.Artifact.PURL); err != nil || !hasVer {
		return nil, &api.AdapterError{
			Code:      api.ErrUnsupportedInput,
			Message:   "osv adapter requires a versioned PURL",
			Retryable: false,
		}
	}

	var (
		vulns    []osvVulnerability
		rawPages []json.RawMessage
		err      error
	)
	if a.cfg.OfflineDemo {
		vulns, rawPages = offlineFixtureForPURL(req.Artifact.PURL)
	} else {
		vulns, rawPages, err = a.queryWithFallback(ctx, req.Artifact.PURL)
		if err != nil {
			return nil, err
		}
	}

	return buildOSVResult(req, vulns, rawPages)
}
