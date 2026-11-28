// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package ossindex

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file implements the HTTP client for Sonatype Guide's OSS Index
// Compatibility API (POST /api/v3/component-report), including preemptive Basic
// authentication and error classification (#95, #97).

const (
	// componentReportEndpoint is the OSS Index v3 component-report path supported
	// by Sonatype Guide's OSS Index Compatibility API (#95).
	componentReportEndpoint = "/api/v3/component-report"

	// versionEndpoint is the OSS Index v3 status/version path used by
	// CheckAvailability to verify reachability and credentials without querying a package.
	versionEndpoint = "/api/v3/version"

	// maxResponseBytes bounds the size of a single upstream OSS Index HTTP response
	// body (16 MiB) so a misbehaving server cannot exhaust gateway memory.
	maxResponseBytes = 16 * 1024 * 1024
)

// queryComponentReport sends a single PURL coordinate to POST /api/v3/component-report
// and decodes the returned ComponentReport array.
func (a *Adapter) queryComponentReport(
	ctx context.Context,
	coordinate string,
) ([]ComponentReport, []byte, error) {
	if !a.cfg.AllowAnonymous && !a.cfg.HasCredentials() {
		return nil, nil, &adapter.AdapterError{
			Code:      adapter.ErrAuthFailed,
			Message:   "OSS Index credentials are not configured",
			Retryable: false,
		}
	}

	reqBody, err := json.Marshal(ComponentReportRequest{
		Coordinates: []string{coordinate},
	})
	if err != nil {
		return nil, nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: "failed to encode OSS Index component-report request",
			Cause:   err,
		}
	}

	rawBody, err := a.doJSONRequest(ctx, componentReportEndpoint, reqBody)
	if err != nil {
		return nil, nil, err
	}

	var reports []ComponentReport
	if err := json.Unmarshal(rawBody, &reports); err != nil {
		return nil, nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: "OSS Index /api/v3/component-report response is not a valid JSON array",
			Cause:   err,
		}
	}
	if len(reports) == 0 {
		return nil, nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: "OSS Index /api/v3/component-report returned an empty component array",
		}
	}

	for _, rep := range reports {
		for _, v := range rep.Vulnerabilities {
			if strings.TrimSpace(v.ID) == "" {
				return nil, nil, &adapter.AdapterError{
					Code:    adapter.ErrMalformedResponse,
					Message: "OSS Index vulnerability record is missing required id field",
				}
			}
		}
	}

	return reports, rawBody, nil
}

// doJSONRequest executes an authenticated POST request against the configured
// OSS Index BaseURL and maps transport, timeout, auth, rate-limit, and status
// failures to *adapter.AdapterError (#74, #95, #97).
func (a *Adapter) doJSONRequest(
	ctx context.Context,
	endpoint string,
	reqBody []byte,
) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.cfg.BaseURL+endpoint,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return nil, &adapter.AdapterError{
			Code:    adapter.ErrUpstreamUnavailable,
			Message: "failed to build OSS Index HTTP request",
			Cause:   err,
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	a.applyAuth(httpReq)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, adapter.ClassifyTransportError("OSS Index", endpoint, err)
	}
	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, adapter.ClassifyTransportError("OSS Index", endpoint, readErr)
	}
	if len(rawBody) > maxResponseBytes {
		return nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: "OSS Index response exceeded maximum allowed size",
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, adapter.ClassifyHTTPStatusError("OSS Index", endpoint, resp.StatusCode)
	}
	return rawBody, nil
}

// applyAuth attaches preemptive HTTP Basic credentials to req.
// Preemptive authentication is required because Sonatype Guide's OSS Index
// Compatibility API rejects unauthenticated requests with HTTP 401/402 rather
// than issuing a challenge-response cycle (#95).
func (a *Adapter) applyAuth(req *http.Request) {
	if a.cfg.Token == "" {
		return
	}
	user := a.cfg.Username
	if user == "" {
		user = defaultPATUsername
	}
	req.SetBasicAuth(user, a.cfg.Token)
}
