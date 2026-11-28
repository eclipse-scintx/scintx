// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import (
	"net/url"
	"strings"
)

// This file keeps secrets out of the provider endpoint recorded in
// ProviderReport.ResponseMetadata (#98).

// RedactEndpoint returns rawURL in a form that is safe to store in a report.
// It keeps the scheme, host, and path. It drops the user info, the query, and
// the fragment.
//
// A base URL may carry credentials, for example
// "https://user:token@mirror.example/osv" or "...?api_key=secret".
// ValidateBaseURL accepts such URLs, and reports are returned to API clients,
// so the raw value must not be copied into a report.
// An unparsable URL yields "" so nothing is leaked by accident.
func RedactEndpoint(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	safe := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}
	return safe.String()
}
