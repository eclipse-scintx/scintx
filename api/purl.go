// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var namespaceLowerTypes = map[string]bool{
	"pypi": true, "npm": true, "gem": true, "composer": true, "golang": true,
}

var purlRe = regexp.MustCompile(`^pkg:([^/#?]+)((?:/[^?#]*)?)(([?#].*)?)$`)

type parsedPurl struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
	Subpath    string
	Hash       string
}

func parsePurl(purl string) (*parsedPurl, error) {
	m := purlRe.FindStringSubmatch(purl)
	if m == nil {
		return nil, fmt.Errorf("invalid purl: %s", purl)
	}
	typ := strings.ToLower(m[1])
	rest := m[2]
	tail := m[3]

	p := &parsedPurl{Type: typ, Qualifiers: map[string]string{}}
	if len(rest) > 0 {
		body := rest[1:]
		if slashIdx := strings.Index(body, "/"); slashIdx >= 0 {
			p.Namespace = body[:slashIdx]
			p.Name = body[slashIdx+1:]
		} else {
			p.Name = body
		}
	}
	if idx := strings.Index(p.Name, "@"); idx >= 0 {
		p.Version = p.Name[idx+1:]
		p.Name = p.Name[:idx]
	}
	if p.Name == "" {
		return nil, fmt.Errorf("invalid purl: missing package name in %s", purl)
	}

	if len(tail) > 0 && tail[0] == '?' {
		body := tail[1:]
		if idx := strings.Index(body, "#"); idx >= 0 {
			p.Hash = body[idx+1:]
			body = body[:idx]
		}
		for _, kv := range strings.Split(body, "&") {
			if eq := strings.Index(kv, "="); eq > 0 {
				p.Qualifiers[strings.ToLower(kv[:eq])] = kv[eq+1:]
			}
		}
	} else if len(tail) > 0 && tail[0] == '#' {
		p.Hash = tail[1:]
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
	if p.Hash != "" {
		fmt.Fprintf(&b, "#%s", p.Hash)
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

// extractVSIXPURL inspects a ZIP/VSIX archive for extension/package.json and builds
// a pkg:vscode-extension/<publisher>/<name>@<version> PURL when present (#67).
func extractVSIXPURL(content []byte) string {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return ""
	}
	for _, f := range zr.File {
		if f.Name != "extension/package.json" && f.Name != "package.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return ""
		}
		data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		_ = rc.Close()
		if err != nil {
			return ""
		}
		var manifest struct {
			Publisher string `json:"publisher"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.Name == "" || manifest.Publisher == "" {
			return ""
		}
		raw := fmt.Sprintf("pkg:vscode-extension/%s/%s", manifest.Publisher, manifest.Name)
		if manifest.Version != "" {
			raw += "@" + manifest.Version
		}
		if cp, err := CanonicalPurl(raw); err == nil {
			return cp
		}
	}
	return ""
}
