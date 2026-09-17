#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Remove build artifacts.
# Usage: ./scripts/clean.sh

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

log "cleaning bin/ and go test cache for this module"
rm -rf "${BIN_DIR}"
go clean -testcache
log "clean ok"
