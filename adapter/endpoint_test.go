// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package adapter

import "testing"

// TestRedactEndpoint verifies that credentials in a provider base URL never
// reach the value stored in a report (#98).
func TestRedactEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.osv.dev":                            "https://api.osv.dev",
		"https://mirror.example:8443/osv":                "https://mirror.example:8443/osv",
		"https://user:token@mirror.example/osv":          "https://mirror.example/osv",
		"https://mirror.example/osv?api_key=secret#frag": "https://mirror.example/osv",
		" https://user@mirror.example ":                  "https://mirror.example",
		"://bad":                                         "",
		"":                                               "",
		"not a url":                                      "",
	} {
		if got := RedactEndpoint(in); got != want {
			t.Fatalf("RedactEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}
