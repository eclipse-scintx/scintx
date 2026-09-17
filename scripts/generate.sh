#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Regenerate extension aggregation packages (extensions/*/all/all.go).
# Usage: ./scripts/generate.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "go generate ./extensions/..."
go generate ./extensions/...
# Keep generated aggregators gofmt-clean so ./scripts/check.sh stays green.
mapfile -t generated < <(find extensions -path '*/all/all.go' | sort)
if [[ ${#generated[@]} -gt 0 ]]; then
  gofmt -w "${generated[@]}"
fi
log "generate ok"
