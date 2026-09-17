#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Run tests with coverage summary (race when CGO is available).
# Usage: ./scripts/test-coverage.sh
# Writes coverage profile to coverage.out and prints per-package + total.
# Set COVER_PROFILE=0 to skip the profile file.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

args=(./...)
if have_cgo; then
  log "go test -race -coverprofile=coverage.out ${args[*]}"
  CGO_ENABLED=1 go test -race -coverprofile=coverage.out "${args[@]}"
else
  log "no C compiler found — running plain go test with coverage"
  go test -coverprofile=coverage.out "${args[@]}"
fi

log "coverage per package:"
go tool cover -func=coverage.out | awk '$1 != "total:" { print }'
log "total:"
go tool cover -func=coverage.out | awk '$1 == "total:" { print }'