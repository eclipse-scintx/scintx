// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yeeth-security/scintx/api"
)

// normalizeExpr collapses whitespace and newlines in a multi-line policy `when` expression.
func normalizeExpr(expr string) string {
	return strings.Join(strings.Fields(expr), " ")
}

var (
	findingExprRe     = regexp.MustCompile(`^([a-z_]+)\.findings\.any\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=>\s*[a-zA-Z_][a-zA-Z0-9_]*\.([a-zA-Z_]+)\s*(==|!=)\s*"([^"]*)"\s*\)$`)
	providerRunExprRe = regexp.MustCompile(`^aggregateReport\.providerRuns\.any\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=>\s*[a-zA-Z_][a-zA-Z0-9_]*\.(status|error\.code)\s*(==|!=)\s*"([^"]*)"\s*\)$`)
	providerAvExprRe  = regexp.MustCompile(`^aggregateReport\.providers\.any\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=>\s*[a-zA-Z_][a-zA-Z0-9_]*\.slug\s*==\s*"([^"]+)"\s*&&\s*![a-zA-Z_][a-zA-Z0-9_]*\.available\s*\)$`)
)

// parsedExpr represents a validated rule condition in a SCINTX policy (#68).
type parsedExpr struct {
	target     string // "findings", "providerRuns", or "providers"
	capability api.Capability
	field      string
	op         string
	value      string
}

// parseExpression parses a policy `when` expression into a structured predicate.
func parseExpression(raw string) (*parsedExpr, error) {
	norm := normalizeExpr(raw)
	if m := findingExprRe.FindStringSubmatch(norm); m != nil {
		return &parsedExpr{
			target:     "findings",
			capability: api.NormalizeCapability(m[1]),
			field:      m[2],
			op:         m[3],
			value:      m[4],
		}, nil
	}
	if m := providerRunExprRe.FindStringSubmatch(norm); m != nil {
		return &parsedExpr{
			target: "providerRuns",
			field:  m[1],
			op:     m[2],
			value:  m[3],
		}, nil
	}
	if m := providerAvExprRe.FindStringSubmatch(norm); m != nil {
		return &parsedExpr{
			target: "providers",
			field:  "slug",
			op:     "==",
			value:  m[1],
		}, nil
	}
	return nil, fmt.Errorf("unsupported policy expression %q", norm)
}

func matchFindingField(f api.Finding, field, op, val string) bool {
	switch field {
	case "type":
		return compareString(f.Type, op, val)
	case "severity":
		return compareString(string(f.Severity), op, val)
	case "id":
		return compareString(f.ID, op, val)
	}
	return false
}

func compareString(actual, op, expected string) bool {
	if op == "==" {
		return actual == expected
	}
	if op == "!=" {
		return actual != expected
	}
	return false
}
