#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# go mod tidy — keep go.mod (and go.sum when deps exist) consistent.
# Usage: ./scripts/tidy.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "go mod tidy"
go mod tidy
log "tidy ok"
