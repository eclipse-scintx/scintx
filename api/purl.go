// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MaxPurlLength caps the total byte length of a submitted Package URL.
const MaxPurlLength = 2048

var namespaceLowerTypes = map[string]bool{
	"pypi": true, "npm": true, "gem": true, "composer": true, "golang": true,
}

var (
	purlRe         = regexp.MustCompile(`^pkg:([^/#?]+)((?:/[^?#]*)?)(([?#].*)?)$`)
	purlTypeRe     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9.+-]*$`)
	qualifierKeyRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*$`)
)

type parsedPurl struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
}

func hasControlOrSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func validatePathSegments(path string) error {
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid path segment %q", seg)
		}
	}
	return nil
}

func parsePurl(purl string) (*parsedPurl, error) {
	if len(purl) == 0 || len(purl) > MaxPurlLength {
		return nil, fmt.Errorf("invalid purl length: %d", len(purl))
	}
	if hasControlOrSpace(purl) {
		return nil, fmt.Errorf("invalid purl: contains whitespace or control characters")
	}

	m := purlRe.FindStringSubmatch(purl)
	if m == nil {
		return nil, fmt.Errorf("invalid purl: %s", purl)
	}
	rawType := m[1]
	if !purlTypeRe.MatchString(rawType) {
		return nil, fmt.Errorf("invalid purl type: %q", rawType)
	}
	typ := strings.ToLower(rawType)
	rest := m[2]
	tail := m[3]

	p := &parsedPurl{Type: typ, Qualifiers: map[string]string{}}
	if len(rest) > 0 {
		body := rest[1:]
		if lastSlash := strings.LastIndex(body, "/"); lastSlash >= 0 {
			p.Namespace = body[:lastSlash]
			p.Name = body[lastSlash+1:]
		} else {
			p.Name = body
		}
	}

	if idx := strings.Index(p.Name, "@"); idx >= 0 {
		p.Version = p.Name[idx+1:]
		p.Name = p.Name[:idx]
		if p.Version == "" || strings.Contains(p.Version, "@") {
			return nil, fmt.Errorf("invalid purl version in %s", purl)
		}
	}
	if p.Name == "" || p.Name == "." || p.Name == ".." || strings.Contains(p.Namespace, "@") {
		return nil, fmt.Errorf("invalid purl package coordinates in %s", purl)
	}
	if p.Namespace != "" {
		if err := validatePathSegments(p.Namespace); err != nil {
			return nil, fmt.Errorf("invalid purl namespace: %w", err)
		}
	}

	if len(tail) > 0 && tail[0] == '?' {
		body := tail[1:]
		if idx := strings.Index(body, "#"); idx >= 0 {
			p.Subpath = body[idx+1:]
			body = body[:idx]
		}
		if body == "" {
			return nil, fmt.Errorf("invalid purl: empty qualifiers")
		}
		for _, kv := range strings.Split(body, "&") {
			eq := strings.Index(kv, "=")
			if eq <= 0 || eq == len(kv)-1 {
				return nil, fmt.Errorf("invalid purl qualifier %q", kv)
			}
			k := strings.ToLower(kv[:eq])
			v := kv[eq+1:]
			if !qualifierKeyRe.MatchString(k) || strings.Contains(v, "=") {
				return nil, fmt.Errorf("invalid purl qualifier %q", kv)
			}
			if _, exists := p.Qualifiers[k]; exists {
				return nil, fmt.Errorf("duplicate purl qualifier %q", k)
			}
			p.Qualifiers[k] = v
		}
	} else if len(tail) > 0 && tail[0] == '#' {
		p.Subpath = tail[1:]
		if p.Subpath == "" {
			return nil, fmt.Errorf("invalid purl: empty subpath")
		}
	}

	if p.Subpath != "" {
		if err := validatePathSegments(p.Subpath); err != nil {
			return nil, fmt.Errorf("invalid purl subpath: %w", err)
		}
	}

	if namespaceLowerTypes[typ] {
		p.Namespace = strings.ToLower(p.Namespace)
		p.Name = strings.ToLower(p.Name)
	}
	return p, nil
}

// CanonicalPurl validates and normalizes a Package URL string.
func CanonicalPurl(purl string) (string, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "pkg:%s", p.Type)
	if p.Namespace != "" {
		fmt.Fprintf(&b, "/%s", p.Namespace)
	}
	fmt.Fprintf(&b, "/%s", p.Name)
	if p.Version != "" {
		fmt.Fprintf(&b, "@%s", p.Version)
	}
	if len(p.Qualifiers) > 0 {
		keys := make([]string, 0, len(p.Qualifiers))
		for k := range p.Qualifiers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		qs := make([]string, 0, len(keys))
		for _, k := range keys {
			qs = append(qs, fmt.Sprintf("%s=%s", k, p.Qualifiers[k]))
		}
		fmt.Fprintf(&b, "?%s", strings.Join(qs, "&"))
	}
	if p.Subpath != "" {
		fmt.Fprintf(&b, "#%s", p.Subpath)
	}
	return b.String(), nil
}

// PurlType returns the lowercase ecosystem type of a Package URL.
func PurlType(purl string) (string, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", err
	}
	return p.Type, nil
}

// PurlVersion returns the version component of a Package URL and whether it is present.
func PurlVersion(purl string) (string, bool, error) {
	p, err := parsePurl(purl)
	if err != nil {
		return "", false, err
	}
	return p.Version, p.Version != "", nil
}
