// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package osv

import (
	"strings"

	"github.com/eclipse-scintx/scintx/adapter"
)

// This file extracts normalized SCINTX adapter.Severity values from OSV
// advisory records using the shared adapter severity helpers (#94, #98).

// metaKeyUrgency is used by Debian, Ubuntu, and Alpine OSV advisories under
// affected[].ecosystem_specific to record qualitative urgency ratings.
const metaKeyUrgency = "urgency"

// extractSeverity maps an OSV record's severity fields to SCINTX Severity.
// It checks MAL-* malware advisories first, then database_specific and
// affected[].ecosystem_specific/database_specific labels (including Debian/Ubuntu
// urgency), and finally CVSS scores/vectors in severity[].score.
func extractSeverity(v Vulnerability) adapter.Severity {
	if strings.HasPrefix(v.ID, malwareIDPrefix) {
		return adapter.SeverityCritical
	}

	if sev, ok := severityFromMap(v.DatabaseSpecific); ok {
		return sev
	}
	for _, aff := range v.Affected {
		if sev, ok := severityFromMap(aff.EcosystemSpecific); ok {
			return sev
		}
		if sev, ok := severityFromMap(aff.DatabaseSpecific); ok {
			return sev
		}
	}

	for _, s := range v.Severity {
		if sev, ok := adapter.SeverityFromCVSSScore(s.Score); ok {
			return sev
		}
	}
	for _, aff := range v.Affected {
		for _, s := range aff.Severity {
			if sev, ok := adapter.SeverityFromCVSSScore(s.Score); ok {
				return sev
			}
		}
	}

	return adapter.SeverityUnknown
}

func severityFromMap(m map[string]any) (adapter.Severity, bool) {
	if len(m) == 0 {
		return "", false
	}
	for _, key := range []string{adapter.MetaKeySeverity, metaKeyUrgency} {
		if raw, ok := m[key].(string); ok {
			if sev, parsed := adapter.ParseSeverityLabel(raw); parsed {
				return sev, true
			}
		}
	}
	return "", false
}
