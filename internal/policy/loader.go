// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package policy loads, validates, and evaluates SCINTX YAML policies against
// Aggregate Reports as specified in issues #68, #69, #72, and #75.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yeeth-security/scintx/api"
	"gopkg.in/yaml.v3"
)

var capabilityRefRe = regexp.MustCompile(`\b([a-z_]+)\.findings\.any\s*\(`)

// LoadDir reads and validates all *.yaml and *.yml policy files in dir (#68, #73).
// It returns a map keyed by each policy's unique ID.
func LoadDir(dir string) (map[string]*api.PolicyDefinition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policies directory %q: %w", dir, err)
	}

	policies := make(map[string]*api.PolicyDefinition)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		fullPath := filepath.Join(dir, name)
		pol, err := LoadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("policy file %q: %w", fullPath, err)
		}
		if _, exists := policies[pol.ID]; exists {
			return nil, fmt.Errorf("duplicate policy id %q in %q", pol.ID, fullPath)
		}
		policies[pol.ID] = pol
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("no policy files found in %q", dir)
	}
	return policies, nil
}

// LoadFile reads, parses, and validates a single YAML policy file (#68).
func LoadFile(path string) (*api.PolicyDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAndValidate(data)
}

// ParseAndValidate parses YAML bytes into a PolicyDefinition and validates
// schemaVersion, identifiers, capabilities, evaluationDeadline, and rule expressions (#68, #69).
func ParseAndValidate(data []byte) (*api.PolicyDefinition, error) {
	var pol api.PolicyDefinition
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	if err := Validate(&pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

// Validate checks that a PolicyDefinition conforms to all static rules in #68 and #69.
// Specifically:
//   - schemaVersion must be "1"
//   - id and version must be non-empty
//   - capabilities must be non-empty and contain only recognized SCINTX capabilities
//   - every capability referenced by a violation or annotation expression must appear in capabilities
//   - every rule expression must have valid, supported syntax
func Validate(pol *api.PolicyDefinition) error {
	if pol == nil {
		return fmt.Errorf("policy is nil")
	}
	if pol.SchemaVersion != api.SchemaVersionV1 {
		return fmt.Errorf("unsupported policy schemaVersion %q (expected %q)", pol.SchemaVersion, api.SchemaVersionV1)
	}
	if strings.TrimSpace(pol.ID) == "" {
		return fmt.Errorf("policy id is required")
	}
	if strings.TrimSpace(pol.Version) == "" {
		return fmt.Errorf("policy version is required")
	}
	if len(pol.Capabilities) == 0 {
		return fmt.Errorf("policy %q must declare at least one capability", pol.ID)
	}

	declared := make(map[api.Capability]bool, len(pol.Capabilities))
	for i, rawCap := range pol.Capabilities {
		norm := api.NormalizeCapability(string(rawCap))
		if !api.ValidCapabilities[norm] {
			return fmt.Errorf("policy %q declares unknown capability %q", pol.ID, rawCap)
		}
		pol.Capabilities[i] = norm
		declared[norm] = true
	}

	if strings.TrimSpace(pol.EvaluationDeadline) == "" {
		pol.EvaluationDeadline = "30s"
	}
	d, err := time.ParseDuration(pol.EvaluationDeadline)
	if err != nil || d <= 0 {
		return fmt.Errorf("policy %q has invalid evaluationDeadline %q", pol.ID, pol.EvaluationDeadline)
	}
	pol.ParsedDeadline = d

	if err := validateRuleMap(pol.ID, "violation", pol.Violations, declared); err != nil {
		return err
	}
	if err := validateRuleMap(pol.ID, "annotation", pol.Annotations, declared); err != nil {
		return err
	}
	return nil
}

func validateRuleMap(policyID, kind string, rules map[string]api.PolicyRule, declared map[api.Capability]bool) error {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		rule := rules[id]
		expr := strings.TrimSpace(rule.When)
		if expr == "" {
			return fmt.Errorf("policy %q %s %q is missing a 'when' expression", policyID, kind, id)
		}
		for _, m := range capabilityRefRe.FindAllStringSubmatch(expr, -1) {
			refCap := api.NormalizeCapability(m[1])
			if !api.ValidCapabilities[refCap] {
				return fmt.Errorf("policy %q %s %q references unknown capability %q", policyID, kind, id, m[1])
			}
			if !declared[refCap] {
				return fmt.Errorf("policy %q %s %q references undeclared capability %q", policyID, kind, id, refCap)
			}
		}
		if _, err := parseExpression(expr); err != nil {
			return fmt.Errorf("policy %q %s %q has invalid expression: %w", policyID, kind, id, err)
		}
	}
	return nil
}
