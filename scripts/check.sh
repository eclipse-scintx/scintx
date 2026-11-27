#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Full local CI: fmt check, license headers, vet, lint, tests, schemas.
# Usage: ./scripts/check.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "check: format (gofmt -l must be empty)"
mapfile -t gofiles < <(find . -name '*.go' ! -path './.git/*' | sort)
unformatted="$(gofmt -l "${gofiles[@]}")"
if [[ -n "${unformatted}" ]]; then
  printf '%s\n' "${unformatted}" >&2
  die "gofmt needed on the files above; run ./scripts/fmt.sh"
fi

log "check: license headers (SPDX-License-Identifier: EPL-2.0)"
"${SCRIPTS_DIR}/headers.sh"

"${SCRIPTS_DIR}/vet.sh"
# The linter runs after vet and before the tests. It is fast, so a finding
# shows up before the slow test run starts. Before this line was added, CI
# installed golangci-lint but nothing ever ran it.
"${SCRIPTS_DIR}/lint.sh"
"${SCRIPTS_DIR}/test-race.sh"
"${SCRIPTS_DIR}/schemas.sh"

log "check ok"
