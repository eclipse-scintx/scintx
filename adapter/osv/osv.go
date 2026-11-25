// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package osv implements the Eclipse SCINTX provider adapter for the OSV.dev
// vulnerability and malware advisory API (#94).
package osv

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/eclipse-scintx/scintx/adapter"
)

const (
	// DefaultBaseURL is the public OSV.dev HTTP API endpoint.
	DefaultBaseURL = "https://api.osv.dev"

	// AdapterSlug is the stable provider identifier for OSV in policies and reports.
	AdapterSlug = "osv"

	// AdapterVersion is the semantic version of this OSV adapter implementation.
	AdapterVersion = "1.0.0"

	// DefaultTimeout bounds each HTTP request when no custom http.Client is supplied.
	DefaultTimeout = 30 * time.Second

	// probePURL is the canonical PURL sent during CheckAvailability probes.
	probePURL = "pkg:npm/lodash@4.17.21"
)

// supportedPURLTypes lists the Package URL ecosystems supported by OSV.dev
// using the shared adapter.Ecosystem constants (#71, #96).
var supportedPURLTypes = []adapter.Ecosystem{
	adapter.EcosystemNPM,
	adapter.EcosystemPyPI,
	adapter.EcosystemMaven,
	adapter.EcosystemGolang,
	adapter.EcosystemCargo,
	adapter.EcosystemGem,
	adapter.EcosystemNuGet,
	adapter.EcosystemComposer,
	adapter.EcosystemHex,
	adapter.EcosystemPub,
	adapter.EcosystemSwift,
	adapter.EcosystemCRAN,
	adapter.EcosystemBioconductor,
	adapter.EcosystemHackage,
	adapter.EcosystemConan,
	adapter.EcosystemDebian,
	adapter.EcosystemAlpine,
	adapter.EcosystemUbuntu,
	adapter.EcosystemRocky,
	adapter.EcosystemAlmaLinux,
	adapter.EcosystemVSCodeExtension,
}

// Config holds endpoint and optional mirror authentication settings for the OSV adapter.
type Config struct {
	// BaseURL overrides DefaultBaseURL when pointing at an OSV mirror or test server.
	BaseURL string

	// RequireAuth indicates whether the configured BaseURL is a private mirror
	// that requires a non-empty BearerToken.
	RequireAuth bool

	// BearerToken is sent as "Authorization: Bearer <token>" when non-empty.
	BearerToken string
}

// Adapter implements adapter.ProviderAdapter for the OSV.dev HTTP API.
type Adapter struct {
	cfg        Config
	httpClient *http.Client
}

// NewAdapter constructs an OSV Adapter with sensible defaults for BaseURL and httpClient.
func NewAdapter(cfg Config, httpClient *http.Client) *Adapter {
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.BearerToken = strings.TrimSpace(cfg.BearerToken)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Adapter{
		cfg:        cfg,
		httpClient: httpClient,
	}
}

// Descriptor returns static metadata about the OSV adapter, its supported PURL
// ecosystems, and the checks it implements under vulnerabilities and threats.
func (a *Adapter) Descriptor() adapter.AdapterDescriptor {
	ecosystems := make([]adapter.Ecosystem, len(supportedPURLTypes))
	copy(ecosystems, supportedPURLTypes)

	return adapter.AdapterDescriptor{
		Slug:                   AdapterSlug,
		AdapterVersion:         AdapterVersion,
		SupportedSchemaVersion: adapter.SchemaVersionV1,
		SupportedInputs: adapter.SupportedInputs{
			Types:      []adapter.ArtifactInputType{adapter.InputTypePURL},
			Ecosystems: ecosystems,
		},
		Capabilities: map[adapter.Capability]adapter.CapabilityDescriptor{
			adapter.CapabilityVulnerabilities: {
				Checks: []adapter.Check{adapter.CheckKnownVulnerabilities},
			},
			adapter.CapabilityThreats: {
				Checks: []adapter.Check{adapter.CheckMalware},
			},
		},
	}
}

// CheckAvailability validates the adapter's configuration, optional mirror
// credentials, and upstream reachability against POST /v1/query using the
// shared adapter availability constructors (#70, #73, #74).
func (a *Adapter) CheckAvailability(ctx context.Context) adapter.AvailabilityStatus {
	if status, ok := adapter.ValidateBaseURL("OSV", a.cfg.BaseURL); !ok {
		return status
	}

	if a.cfg.RequireAuth && a.cfg.BearerToken == "" {
		return adapter.NewUnconfiguredStatus(
			adapter.ReasonMissingCredentials,
			"OSV mirror requires a bearer token, but none is configured",
		)
	}

	probeBody := []byte(`{"package":{"purl":"` + probePURL + `"}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.BaseURL+queryEndpoint, bytes.NewReader(probeBody))
	if err != nil {
		return adapter.NewUnconfiguredStatus(
			adapter.ReasonInvalidConfiguration,
			"failed to construct OSV availability probe request",
		)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.BearerToken)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return adapter.NewUnreachableStatus(
			adapter.ReasonUpstreamUnreachable,
			"failed to reach OSV API",
		)
	}
	_ = resp.Body.Close()

	return adapter.AvailabilityFromHTTPStatus("OSV", resp.StatusCode)
}
