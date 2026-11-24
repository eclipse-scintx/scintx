// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

type osvQueryRequest struct {
	Package   *osvPackage `json:"package,omitempty"`
	Version   string      `json:"version,omitempty"`
	PageToken string      `json:"page_token,omitempty"`
}

type osvPackage struct {
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
}

type osvQueryResponse struct {
	Vulns         []osvVulnerability `json:"vulns"`
	NextPageToken string             `json:"next_page_token,omitempty"`
}

type osvVulnerability struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// queryWithFallback queries OSV POST /v1/query by PURL, and falls back to
// the Open VSX ecosystem query if the package is a vscode-extension (#43, #70).
func (a *Adapter) queryWithFallback(ctx context.Context, purl string) ([]osvVulnerability, []json.RawMessage, error) {
	vulns, pages, err := a.queryAllPages(ctx, osvQueryRequest{
		Package: &osvPackage{PURL: purl},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(vulns) == 0 && strings.HasPrefix(purl, "pkg:vscode-extension/") {
		if extName, version, ok := parseVSCodeExtensionPURL(purl); ok {
			fbVulns, fbPages, fbErr := a.queryAllPages(ctx, osvQueryRequest{
				Package: &osvPackage{
					Ecosystem: "VSCode:https://open-vsx.org",
					Name:      extName,
				},
				Version: version,
			})
			if fbErr != nil {
				return nil, nil, fbErr
			}
			vulns = fbVulns
			pages = append(pages, fbPages...)
		}
	}
	return vulns, pages, nil
}

// queryAllPages calls POST /v1/query and follows next_page_token until exhausted (#70, #74).
func (a *Adapter) queryAllPages(
	ctx context.Context,
	baseReq osvQueryRequest,
) ([]osvVulnerability, []json.RawMessage, error) {
	var all []osvVulnerability
	var pages []json.RawMessage
	pageToken := ""

	for {
		baseReq.PageToken = pageToken
		body, err := json.Marshal(baseReq)
		if err != nil {
			return nil, nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.BaseURL+"/v1/query", bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
		if a.cfg.BearerToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+a.cfg.BearerToken)
		}

		resp, err := a.httpClient.Do(httpReq)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, nil, &api.AdapterError{
					Code:      api.ErrTimeout,
					Message:   "OSV request timed out",
					Retryable: true,
					Cause:     err,
				}
			}
			return nil, nil, &api.AdapterError{
				Code:      api.ErrUpstreamUnavailable,
				Message:   "failed to reach OSV /v1/query endpoint",
				Retryable: true,
				Cause:     err,
			}
		}

		rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, nil, &api.AdapterError{
				Code:      api.ErrUpstreamUnavailable,
				Message:   "failed to read OSV response body",
				Retryable: true,
				Cause:     readErr,
			}
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, nil, &api.AdapterError{
				Code:      api.ErrAuthFailed,
				Message:   fmt.Sprintf("OSV authentication failed with HTTP %d", resp.StatusCode),
				Retryable: false,
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, nil, &api.AdapterError{
				Code:      api.ErrRateLimited,
				Message:   "OSV API rate limit exceeded",
				Retryable: true,
			}
		}
		if resp.StatusCode != http.StatusOK {
			return nil, nil, &api.AdapterError{
				Code:      api.ErrUpstreamUnavailable,
				Message:   fmt.Sprintf("OSV /v1/query returned HTTP %d", resp.StatusCode),
				Retryable: resp.StatusCode >= 500,
			}
		}

		var page osvQueryResponse
		if err := json.Unmarshal(rawBody, &page); err != nil {
			return nil, nil, &api.AdapterError{
				Code:      api.ErrMalformedResponse,
				Message:   "OSV /v1/query response is not valid JSON",
				Retryable: false,
				Cause:     err,
			}
		}
		all = append(all, page.Vulns...)
		pages = append(pages, rawBody)

		if page.NextPageToken == "" {
			break
		}
		pageToken = page.NextPageToken
	}
	return all, pages, nil
}
