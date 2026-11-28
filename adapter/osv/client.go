// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

const (
	// queryEndpoint is the OSV HTTP v1 package query path.
	queryEndpoint = "/v1/query"

	// queryBatchEndpoint is the OSV HTTP v1 batch query path, used with an empty
	// queries array during CheckAvailability probes so no package is hardcoded.
	queryBatchEndpoint = "/v1/querybatch"

	// vulnsEndpointPrefix is the OSV HTTP v1 single-record retrieval path prefix.
	vulnsEndpointPrefix = "/v1/vulns/"

	// maxResponseBytes bounds the size of a single upstream OSV HTTP response body
	// (16 MiB) so a misbehaving server cannot exhaust gateway memory.
	maxResponseBytes = 16 * 1024 * 1024

	// maxQueryPages caps how many pagination tokens queryAllPages will follow for
	// a single package query so a cyclic token cannot loop forever.
	maxQueryPages = 50
)

// queryAllPages calls POST /v1/query and follows next_page_token until all
// matching vulnerability records and raw JSON pages are collected.
func (a *Adapter) queryAllPages(ctx context.Context, baseReq QueryRequest) ([]Vulnerability, []json.RawMessage, error) {
	var all []Vulnerability
	var pages []json.RawMessage
	pageToken := ""

	for pageNum := 0; pageNum < maxQueryPages; pageNum++ {
		baseReq.PageToken = pageToken
		reqBody, err := json.Marshal(baseReq)
		if err != nil {
			return nil, nil, &adapter.AdapterError{
				Code:    adapter.ErrMalformedResponse,
				Message: "failed to encode OSV query request",
				Cause:   err,
			}
		}
		rawBody, err := a.doJSONRequest(ctx, http.MethodPost, queryEndpoint, reqBody)
		if err != nil {
			return nil, nil, err
		}
		var page QueryResponse
		if err := json.Unmarshal(rawBody, &page); err != nil {
			return nil, nil, &adapter.AdapterError{
				Code:    adapter.ErrMalformedResponse,
				Message: "OSV /v1/query response is not valid JSON",
				Cause:   err,
			}
		}
		all = append(all, page.Vulns...)
		pages = append(pages, json.RawMessage(rawBody))
		if page.NextPageToken == "" {
			return all, pages, nil
		}
		if page.NextPageToken == pageToken {
			return nil, nil, &adapter.AdapterError{
				Code:    adapter.ErrMalformedResponse,
				Message: "OSV /v1/query returned a repeating next_page_token",
			}
		}
		pageToken = page.NextPageToken
	}

	return nil, nil, &adapter.AdapterError{
		Code:    adapter.ErrMalformedResponse,
		Message: fmt.Sprintf("OSV /v1/query exceeded %d pagination pages", maxQueryPages),
	}
}

// GetVulnerability retrieves a complete OSV advisory record by ID from
// GET /v1/vulns/{id} (#94).
func (a *Adapter) GetVulnerability(ctx context.Context, id string) (Vulnerability, json.RawMessage, error) {
	trimmedID := strings.TrimSpace(id)
	if trimmedID == "" {
		return Vulnerability{}, nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: "OSV vulnerability ID must not be empty",
		}
	}

	endpoint := vulnsEndpointPrefix + url.PathEscape(trimmedID)
	rawBody, err := a.doJSONRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Vulnerability{}, nil, err
	}

	var vuln Vulnerability
	if err := json.Unmarshal(rawBody, &vuln); err != nil {
		return Vulnerability{}, nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: fmt.Sprintf("OSV %s response is not valid JSON", endpoint),
			Cause:   err,
		}
	}
	if strings.TrimSpace(vuln.ID) == "" {
		return Vulnerability{}, nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: fmt.Sprintf("OSV %s record is missing required id field", endpoint),
		}
	}
	return vuln, json.RawMessage(rawBody), nil
}

// doJSONRequest executes one HTTP call against the configured OSV BaseURL and
// maps transport, timeout, auth, rate-limit, and status errors to *adapter.AdapterError.
func (a *Adapter) doJSONRequest(
	ctx context.Context,
	method string,
	endpoint string,
	reqBody []byte,
) ([]byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		bodyReader = bytes.NewReader(reqBody)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, a.cfg.BaseURL+endpoint, bodyReader)
	if err != nil {
		return nil, &adapter.AdapterError{
			Code:    adapter.ErrUpstreamUnavailable,
			Message: "failed to build OSV HTTP request",
			Cause:   err,
		}
	}
	if reqBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set("Accept", "application/json")
	if a.cfg.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+a.cfg.BearerToken)
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, adapter.ClassifyTransportError("OSV", endpoint, err)
	}
	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, adapter.ClassifyTransportError("OSV", endpoint, readErr)
	}
	if len(rawBody) > maxResponseBytes {
		return nil, &adapter.AdapterError{
			Code:    adapter.ErrMalformedResponse,
			Message: "OSV response exceeded maximum allowed size",
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, adapter.ClassifyHTTPStatusError("OSV", endpoint, resp.StatusCode)
	}
	return rawBody, nil
}
