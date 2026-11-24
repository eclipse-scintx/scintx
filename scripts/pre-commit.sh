#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Fast checks intended for git pre-commit (no race detector, no schema python).
# Usage: ./scripts/pre-commit.sh
# Invoked automatically when hooks are installed (see ./scripts/install-hooks.sh).

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "pre-commit: format"
mapfile -t gofiles < <(find . -name '*.go' ! -path './.git/*' | sort)
unformatted="$(gofmt -l "${gofiles[@]}")"
if [[ -n "${unformatted}" ]]; then
  printf '%s\n' "${unformatted}" >&2
  die "gofmt needed; run: make fmt  (or ./scripts/fmt.sh)"
fi

log "pre-commit: license headers"
"${SCRIPTS_DIR}/headers.sh"

"${SCRIPTS_DIR}/vet.sh"
"${SCRIPTS_DIR}/test.sh"

log "pre-commit ok"
