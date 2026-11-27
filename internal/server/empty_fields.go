// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eclipse-scintx/scintx/api"
)

// This file holds one rule for both request formats (JSON and multipart):
//
//	An artifact field that is SENT counts, even when its value is empty.
//
// An artifact must have exactly one of purl, digest, or content. The check
// for that is api.ValidateAndNormalizeArtifact. But that function gets a Go
// struct, and in a Go struct an empty purl looks the same as no purl at all.
// So a request with an empty purl AND a digest passed as "digest only". The
// same happened with a JSON null in place of any of the three fields.
//
// Only the parser still knows what the client really sent. So the parser
// rejects an empty field, before validation runs. This fails closed: the
// gateway does not guess which of two fields the client meant.
//
// The published schema already demands this (schema/artifact.schema.json:
// exactly one property, and a purl that starts with "pkg:").

// errEmptyField is the error for a field that was sent without a value. It
// wraps api.ErrValidation, so the handler answers 422 like for every other
// validation failure.
func errEmptyField(name string) error {
	return fmt.Errorf("%w: artifact field %q was sent but is empty; give it a value or leave it out", api.ErrValidation, name)
}

// isBlank reports whether a text value is empty or only whitespace.
func isBlank(text string) bool { return strings.TrimSpace(text) == "" }

// rejectEmptyJSONFields looks at the raw JSON body and returns an error if a
// field of "artifact" was sent as null, as "", or as a blank string.
//
// The body has already been decoded once into the request struct, with all
// the strict checks. This second, loose pass only answers one question that
// the struct cannot: which keys did the client send?
func rejectEmptyJSONFields(body []byte) error {
	var sent struct {
		// A map keeps every key the client sent, and RawMessage keeps each
		// value exactly as it was written.
		Artifact map[string]json.RawMessage `json:"artifact"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		return err
	}
	for name, raw := range sent.Artifact {
		// Decoding into a string works for a JSON string and for null (null
		// leaves the string empty). It fails for an object such as a digest.
		// An object is not "empty" in this sense. Validation checks it later.
		var text string
		if json.Unmarshal(raw, &text) == nil && isBlank(text) {
			return errEmptyField(name)
		}
	}
	return nil
}
