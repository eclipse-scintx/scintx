#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Stress-test concurrent gateway and e2e paths.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

export SCINTX_STRESS_SCALE="${SCINTX_STRESS_SCALE:-1}"
log "stress scale=${SCINTX_STRESS_SCALE}"

args=("$@")
log "go test stress packages"
go test -count=1 -timeout=10m \
  ./internal/gateway/ \
  ./test/e2e/ \
  -run 'Stress' \
  "${args[@]}"

log "stress ok"
