// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package api defines the core domain models and provider adapter contract for SCINTX.
//
// These types implement the architecture defined in issues #65 through #75:
//   - Consumers submit an ArtifactInput (PURL, digest, or raw content bytes) and an
//     optional policy identifier.
//   - The gateway selects compatible ProviderAdapter implementations using the active
//     policy's declared capabilities and each adapter's self-declared AdapterDescriptor.
//   - Adapters return normalized ProviderReport values without deduplicating findings.
//   - The gateway snapshots an immutable AggregateReport and evaluates the selected
//     policy to produce a PolicyReport with a satisfied, violated, or undetermined verdict.
package api
