// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package gateway

import (
	"context"
	"errors"
	"time"

	"github.com/yeeth-security/scintx/api"
)

type runOutcome struct {
	index  int
	run    api.ProviderRun
	report *api.ProviderReport
}

// runSelectedProviders executes all selected ProviderAdapter runs concurrently
// until they complete or until evalCtx (the policy's evaluationDeadline) expires (#68, #72, #74).
func (o *Orchestrator) runSelectedProviders(
	evalCtx context.Context,
	sub api.Submission,
	selected []selectedAdapter,
) ([]api.ProviderRun, []api.ProviderReport) {
	startedAt := time.Now().UTC()
	runs := make([]api.ProviderRun, len(selected))
	for i, sel := range selected {
		runs[i] = api.ProviderRun{
			ID:        sel.runID,
			Provider:  sel.adapter.Descriptor().Slug,
			Status:    api.RunStatusIncomplete,
			StartedAt: startedAt,
		}
	}

	outCh := make(chan runOutcome, len(selected))
	for i, sel := range selected {
		go func(idx int, sel selectedAdapter) {
			slug := sel.adapter.Descriptor().Slug
			provTimeout := 30 * time.Second
			if pcfg, ok := o.cfg.Providers[slug]; ok && pcfg.ParsedTimeout > 0 {
				provTimeout = pcfg.ParsedTimeout
			}
			runCtx, cancel := context.WithTimeout(evalCtx, provTimeout)
			defer cancel()

			res, err := sel.adapter.Evaluate(runCtx, api.EvaluationRequest{
				SubmissionID:          sub.ID,
				ProviderRunID:         sel.runID,
				Artifact:              sub.Artifact,
				RequestedCapabilities: sel.matchedCaps,
			})
			finishedAt := time.Now().UTC()
			durMs := finishedAt.Sub(startedAt).Milliseconds()

			// If the policy's evaluationDeadline expired first, leave the run as incomplete (#68, #72, #74).
			if err != nil && errors.Is(evalCtx.Err(), context.DeadlineExceeded) {
				return
			}

			if err != nil {
				var aerr *api.AdapterError
				if !errors.As(err, &aerr) {
					aerr = &api.AdapterError{Code: api.ErrUpstreamUnavailable, Message: err.Error()}
				}
				status := api.RunStatusFailed
				if aerr.Code == api.ErrTimeout {
					status = api.RunStatusTimedOut
				}
				outCh <- runOutcome{
					index: idx,
					run: api.ProviderRun{
						ID:          sel.runID,
						Provider:    slug,
						Status:      status,
						StartedAt:   startedAt,
						CompletedAt: &finishedAt,
						DurationMs:  durMs,
						Error:       aerr,
					},
				}
				return
			}

			rep := res.Report
			if rep.ID == "" {
				rep.ID = api.NewID("report")
			}
			rep.ProviderRunID = sel.runID
			rep.Provider = slug
			if len(res.RawEvidence) > 0 {
				rep.RawEvidenceRef = o.store.PutRawEvidence(res.RawEvidence)
			}
			repID := rep.ID
			outCh <- runOutcome{
				index: idx,
				run: api.ProviderRun{
					ID:          sel.runID,
					Provider:    slug,
					Status:      api.RunStatusCompleted,
					StartedAt:   startedAt,
					CompletedAt: &finishedAt,
					DurationMs:  durMs,
					ReportID:    &repID,
				},
				report: &rep,
			}
		}(i, sel)
	}

	reports := make([]api.ProviderReport, 0, len(selected))
	completedCount := 0
	for completedCount < len(selected) {
		select {
		case out := <-outCh:
			runs[out.index] = out.run
			if out.report != nil {
				reports = append(reports, *out.report)
			}
			completedCount++
		case <-evalCtx.Done():
			now := time.Now().UTC()
			for i := range runs {
				if runs[i].Status == api.RunStatusIncomplete {
					runs[i].DurationMs = now.Sub(startedAt).Milliseconds()
				}
			}
			return runs, reports
		}
	}
	return runs, reports
}

func summarizeRuns(runs []api.ProviderRun) api.ProviderSummary {
	var s api.ProviderSummary
	s.Selected = len(runs)
	for _, r := range runs {
		switch r.Status {
		case api.RunStatusCompleted:
			s.Completed++
		case api.RunStatusFailed:
			s.Failed++
		case api.RunStatusTimedOut:
			s.TimedOut++
		case api.RunStatusIncomplete:
			s.Incomplete++
		}
	}
	return s
}
