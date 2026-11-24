// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package ossindex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/yeeth-security/scintx/api"
)

type reportRequest struct {
	Coordinates []string `json:"coordinates"`
}

type componentReport struct {
	Coordinates     string             `json:"coordinates"`
	Description     string             `json:"description"`
	Reference       string             `json:"reference"`
	Vulnerabilities []ossVulnerability `json:"vulnerabilities"`
}

type ossVulnerability struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CvssScore   *float64 `json:"cvssScore"`
	Cve         string   `json:"cve"`
}

// Evaluate queries Sonatype OSS Index (/api/v3/component-report) and maps results
// into a normalized SCINTX ProviderReport (#70, #72, #74).
func (a *Adapter) Evaluate(ctx context.Context, req api.EvaluationRequest) (*api.EvaluationResult, error) {
	if req.Artifact.PURL == "" {
		return nil, &api.AdapterError{
			Code:      api.ErrUnsupportedInput,
			Message:   "ossindex adapter requires a package PURL",
			Retryable: false,
		}
	}
	if _, hasVer, err := api.PurlVersion(req.Artifact.PURL); err != nil || !hasVer {
		return nil, &api.AdapterError{
			Code:      api.ErrUnsupportedInput,
			Message:   "ossindex adapter requires a versioned PURL",
			Retryable: false,
		}
	}

	rawReq, err := json.Marshal(reportRequest{Coordinates: []string{req.Artifact.PURL}})
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.BaseURL+"/api/v3/component-report", bytes.NewReader(rawReq))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if a.cfg.Token != "" {
		user := a.cfg.Username
		if user == "" {
			user = "scintx"
		}
		httpReq.SetBasicAuth(user, a.cfg.Token)
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &api.AdapterError{
				Code:      api.ErrTimeout,
				Message:   "OSS Index request timed out",
				Retryable: true,
				Cause:     err,
			}
		}
		return nil, &api.AdapterError{
			Code:      api.ErrUpstreamUnavailable,
			Message:   "failed to reach OSS Index API",
			Retryable: true,
			Cause:     err,
		}
	}

	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, &api.AdapterError{
			Code:      api.ErrUpstreamUnavailable,
			Message:   "failed to read OSS Index response body",
			Retryable: true,
			Cause:     readErr,
		}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &api.AdapterError{
			Code:      api.ErrAuthFailed,
			Message:   fmt.Sprintf("OSS Index authentication failed with HTTP %d", resp.StatusCode),
			Retryable: false,
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &api.AdapterError{
			Code:      api.ErrRateLimited,
			Message:   "OSS Index rate limit exceeded",
			Retryable: true,
		}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &api.AdapterError{
			Code:      api.ErrUpstreamUnavailable,
			Message:   fmt.Sprintf("OSS Index returned HTTP %d", resp.StatusCode),
			Retryable: resp.StatusCode >= 500,
		}
	}

	var reports []componentReport
	if err := json.Unmarshal(rawBody, &reports); err != nil {
		return nil, &api.AdapterError{
			Code:      api.ErrMalformedResponse,
			Message:   "OSS Index response is not valid JSON",
			Retryable: false,
			Cause:     err,
		}
	}

	findings := make([]api.Finding, 0)
	for _, comp := range reports {
		for _, v := range comp.Vulnerabilities {
			if v.ID == "" && v.Cve == "" {
				return nil, &api.AdapterError{
					Code:      api.ErrMalformedResponse,
					Message:   "OSS Index vulnerability entry is missing id and cve",
					Retryable: false,
				}
			}
			id := v.ID
			if id == "" {
				id = v.Cve
			}
			var ids []string
			if v.ID != "" {
				ids = append(ids, v.ID)
			}
			if v.Cve != "" && v.Cve != v.ID {
				ids = append(ids, v.Cve)
			}
			findings = append(findings, api.Finding{
				ID:          id,
				Type:        "vulnerability",
				Severity:    mapCVSSScore(v.CvssScore),
				Title:       v.Title,
				Description: v.Description,
				Artifact:    &api.ArtifactInput{PURL: req.Artifact.PURL},
				Identifiers: ids,
			})
		}
	}

	return &api.EvaluationResult{
		Report: api.ProviderReport{
			SchemaVersion:  api.SchemaVersionV1,
			ProviderRunID:  req.ProviderRunID,
			Provider:       "ossindex",
			AdapterVersion: "1.0.0",
			Capabilities: map[api.Capability]api.CapabilityReport{
				api.CapabilityVulnerabilities: {
					Status:   api.CapabilityStatusCompleted,
					Checks:   []api.CheckResult{{ID: "known-vulnerabilities", Status: api.CapabilityStatusCompleted}},
					Findings: findings,
				},
			},
		},
		RawEvidence: rawBody,
	}, nil
}

func mapCVSSScore(score *float64) api.Severity {
	if score == nil {
		return api.SeverityUnknown
	}
	switch {
	case *score >= 9.0:
		return api.SeverityCritical
	case *score >= 7.0:
		return api.SeverityHigh
	case *score >= 4.0:
		return api.SeverityMedium
	case *score > 0:
		return api.SeverityLow
	default:
		return api.SeverityInfo
	}
}
