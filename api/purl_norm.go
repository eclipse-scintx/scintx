// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package api

import (
	"fmt"
	"net/url"
	"strings"
)

// purlEncode percent-encodes every byte that is not unreserved (RFC 3986).
// Hex digits are upper case, which is the Package URL canonical form.
// Slash is not left raw: callers encode one path segment at a time and join
// the segments with "/" themselves.
func purlEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isPurlUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func isPurlUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// decodePurlComponent percent-decodes one purl component. Invalid escapes
// fail closed. A decoded space or control character fails closed too: the
// raw-string check cannot see one that was still percent-encoded.
func decodePurlComponent(raw, what string) (string, error) {
	if raw == "" {
		return "", nil
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("invalid purl %s encoding: %w", what, err)
	}
	if hasControlOrSpace(decoded) {
		return "", fmt.Errorf("invalid purl %s: contains whitespace or control characters", what)
	}
	return decoded, nil
}

// normalizePurlToken decodes one value that is not a path (a version or a
// qualifier) and writes it back in canonical encoding.
func normalizePurlToken(raw, what string) (string, error) {
	decoded, err := decodePurlComponent(raw, what)
	if err != nil {
		return "", err
	}
	return purlEncode(decoded), nil
}

// normalizePurlPath decodes a namespace, name, or subpath. Each "/"-separated
// segment is decoded on its own, so "%2F" is not a separator. "." and ".."
// are rejected after decoding. That is what blocks "%2e%2e", which the raw
// segment check treated as an ordinary name. lower folds the decoded text
// for ecosystems that are not case sensitive.
func normalizePurlPath(raw, what string, lower bool) (string, error) {
	if raw == "" {
		return "", nil
	}
	parts := strings.Split(raw, "/")
	out := make([]string, len(parts))
	for i, part := range parts {
		decoded, err := decodePurlComponent(part, what)
		if err != nil {
			return "", err
		}
		if lower {
			decoded = strings.ToLower(decoded)
		}
		// A decoded slash would rebuild a segment the splitter did not see.
		// ".." after decoding is the traversal form of "%2e%2e".
		if decoded == "" || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, `/\`) {
			return "", fmt.Errorf("invalid purl %s segment %q", what, decoded)
		}
		out[i] = purlEncode(decoded)
	}
	return strings.Join(out, "/"), nil
}
