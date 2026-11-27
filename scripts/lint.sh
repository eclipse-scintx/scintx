#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Run golangci-lint across the module. The rules are in .golangci.yml.
# Usage: ./scripts/lint.sh
#
# Why this script exists: CI installed golangci-lint, but no script ever ran
# it. So lint findings piled up without anyone seeing them. check.sh now
# calls this script, which makes CI fail on a finding.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

if ! command -v golangci-lint >/dev/null 2>&1; then
  # In CI a missing linter is an error. If it were only a warning, a broken
  # install step would turn the lint check off again without anyone noticing.
  # GitHub Actions sets CI=true for every job.
  if [[ -n "${CI:-}" ]]; then
    die "golangci-lint is not installed, and CI must not skip the lint check"
  fi
  # On a developer machine the linter is optional, like the race detector in
  # test-race.sh. The other checks still run. Say clearly that this one did not.
  log "lint SKIPPED: golangci-lint is not installed (see https://golangci-lint.run/docs/welcome/install/)"
  exit 0
fi

# golangci-lint can only check a module whose Go version is not newer than
# the Go it was built with. If it is too old it stops with an error here,
# and the fix is to install a newer golangci-lint (CI pins one in ci.yml).
log "golangci-lint run ./..."
golangci-lint run ./...
log "lint ok"
