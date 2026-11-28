// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package ossindex implements the Eclipse SCINTX provider adapter for Sonatype
// OSS Index against Sonatype Guide's OSS Index Compatibility API (#95).
//
// Endpoint migration (#95):
// Sonatype is retiring the legacy OSS Index endpoint (https://ossindex.sonatype.org)
// on 31 December 2026 as part of the migration to Sonatype Guide. Supported OSS
// Index v3 component-report functionality remains available through Sonatype
// Guide's OSS Index Compatibility API at https://api.guide.sonatype.com. This
// adapter defaults to DefaultBaseURL (https://api.guide.sonatype.com) while
// allowing callers to override Config.BaseURL for mirrors, test servers, or
// LegacyBaseURL prior to sunset.
//
// Authentication (#95):
// Sonatype Guide's OSS Index Compatibility API requires preemptive HTTP
// authentication on every request:
//  1. Sonatype Guide Personal Access Token (PAT) (recommended): set Config.Token
//     to the Guide PAT and optionally set Config.Username to your account email
//     (Sonatype Guide ignores the Basic Auth username field for PATs, and the
//     adapter supplies a default username when Username is omitted).
//  2. Legacy OSS Index token (supported until 31 December 2026): set
//     Config.Username to your OSS Index email and Config.Token to your legacy
//     OSS Index API token.
package ossindex

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/eclipse-scintx/scintx/adapter"
)

const (
	// DefaultBaseURL is Sonatype Guide's OSS Index Compatibility API base URL (#95).
	DefaultBaseURL = "https://api.guide.sonatype.com"

	// LegacyBaseURL is the deprecated OSS Index endpoint scheduled for retirement
	// on 31 December 2026 (#95).
	LegacyBaseURL = "https://ossindex.sonatype.org"

	// AdapterSlug is the stable provider identifier for OSS Index in policies and reports.
	AdapterSlug = "ossindex"

	// AdapterVersion is the semantic version of this OSS Index adapter implementation.
	AdapterVersion = "1.0.0"

	// DefaultTimeout bounds each HTTP request when no custom http.Client is supplied.
	DefaultTimeout = 30 * time.Second

	// defaultPATUsername is used as the HTTP Basic Auth username when Config.Token
	// is set without an explicit Config.Username. Sonatype Guide ignores the Basic
	// Auth username field when authenticating with a Guide PAT (#95).
	defaultPATUsername = "guide"
)

// supportedPURLTypes lists the Package URL ecosystems supported by Sonatype
// OSS Index using the shared adapter.Ecosystem constants (#71, #95, #96).
var supportedPURLTypes = []adapter.Ecosystem{
	adapter.EcosystemCargo,
	adapter.EcosystemCocoapods,
	adapter.EcosystemComposer,
	adapter.EcosystemConan,
	adapter.EcosystemConda,
	adapter.EcosystemCRAN,
	adapter.EcosystemGem,
	adapter.EcosystemGolang,
	adapter.EcosystemMaven,
	adapter.EcosystemNPM,
	adapter.EcosystemNuGet,
	adapter.EcosystemPyPI,
	adapter.EcosystemRPM,
	adapter.EcosystemSwift,
}

// Config holds endpoint and authentication settings for the OSS Index adapter (#95).
type Config struct {
	// BaseURL overrides DefaultBaseURL (https://api.guide.sonatype.com) when
	// pointing at a custom mirror, test server, or LegacyBaseURL.
	BaseURL string

	// Username is the HTTP Basic Auth username (required for legacy OSS Index
	// tokens; optional when Token is a Sonatype Guide PAT).
	Username string

	// Token is the Sonatype Guide PAT or legacy OSS Index API token sent
	// preemptively via HTTP Basic Auth ("Authorization: Basic <base64(user:token)>").
	Token string

	// AllowAnonymous permits unauthenticated requests against local test servers
	// or mirrors that do not require credentials. When false (the default),
	// CheckAvailability reports ReasonMissingCredentials if Token is empty.
	AllowAnonymous bool
}

// HasCredentials reports whether an OSS Index / Sonatype Guide token is configured.
func (c Config) HasCredentials() bool {
	return strings.TrimSpace(c.Token) != ""
}

// Adapter implements adapter.ProviderAdapter for Sonatype Guide's OSS Index Compatibility API.
type Adapter struct {
	cfg        Config
	httpClient *http.Client
}

// NewAdapter constructs an OSS Index Adapter with sensible defaults for BaseURL and httpClient.
func NewAdapter(cfg Config, httpClient *http.Client) *Adapter {
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Adapter{
		cfg:        cfg,
		httpClient: httpClient,
	}
}

// Descriptor returns static metadata about the OSS Index adapter, its supported
// PURL ecosystems, and its known-vulnerabilities check.
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
		},
	}
}

// CheckAvailability validates the adapter's base URL, required credentials,
// and upstream reachability against GET /api/v3/version without querying any
// package coordinate (#70, #73, #95).
func (a *Adapter) CheckAvailability(ctx context.Context) adapter.AvailabilityStatus {
	if status, ok := adapter.ValidateBaseURL("OSS Index", a.cfg.BaseURL); !ok {
		return status
	}

	if !a.cfg.AllowAnonymous && !a.cfg.HasCredentials() {
		return adapter.NewUnconfiguredStatus(
			adapter.ReasonMissingCredentials,
			"OSS Index requires a Sonatype Guide PAT or OSS Index API token",
		)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.BaseURL+versionEndpoint, nil)
	if err != nil {
		return adapter.NewUnconfiguredStatus(
			adapter.ReasonInvalidConfiguration,
			"failed to construct OSS Index availability probe request",
		)
	}
	req.Header.Set("Accept", "application/json")
	a.applyAuth(req)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return adapter.NewUnreachableStatus(
			adapter.ReasonUpstreamUnreachable,
			"failed to reach OSS Index API",
		)
	}
	_ = resp.Body.Close()

	return adapter.AvailabilityFromHTTPStatus("OSS Index", resp.StatusCode)
}
