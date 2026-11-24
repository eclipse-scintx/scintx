#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Deterministic offline demonstration of the SCINTX M1 gateway (#41):
#   1. Builds the gateway binary
#   2. Starts the gateway with deterministic fixtures (no live credentials needed)
#   3. Verifies liveness (/healthz), readiness (/readyz), and CLI health probe
#   4. Submits a valid artifact (POST /v1/submissions)
#   5. Retrieves submission status, Aggregate Report, and Policy Report
#   6. Demonstrates a validation failure (HTTP 422)

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

DEMO_PORT="${SCINTX_DEMO_PORT:-18080}"
DEMO_URL="http://127.0.0.1:${DEMO_PORT}"

"${SCRIPTS_DIR}/build.sh"

log "starting SCINTX gateway on :${DEMO_PORT} (SCINTX_DEMO_FIXTURES=1)"
SCINTX_ADDR="127.0.0.1:${DEMO_PORT}" SCINTX_DEMO_FIXTURES=1 "${BINARY}" serve >/tmp/scintx-demo.log 2>&1 &
GW_PID=$!
trap 'kill "${GW_PID}" >/dev/null 2>&1 || true' EXIT

# Wait for readiness using the built-in container health probe.
for _ in $(seq 1 30); do
  if SCINTX_ADDR="127.0.0.1:${DEMO_PORT}" "${BINARY}" health >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

log "1. Liveness probe (GET /healthz)"
curl -fsS "${DEMO_URL}/healthz"
printf '\n'

log "2. Readiness probe (GET /readyz) and built-in CLI probe (scintx health)"
curl -fsS "${DEMO_URL}/readyz"
printf '\n'
SCINTX_ADDR="127.0.0.1:${DEMO_PORT}" "${BINARY}" health
log "CLI health probe succeeded"

log "3. Submit valid artifact (POST /v1/submissions)"
SUB_JSON="$(curl -fsS -X POST "${DEMO_URL}/v1/submissions" \
  -H 'Content-Type: application/json' \
  -d '{"artifact":{"purl":"pkg:npm/lodash@4.17.20"},"policy":"baseline-security"}')"
printf '%s\n' "${SUB_JSON}"

SUB_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"${SUB_JSON}")"

# Poll until submission reaches completed status.
for _ in $(seq 1 30); do
  STATUS_JSON="$(curl -fsS "${DEMO_URL}/v1/submissions/${SUB_ID}")"
  STATUS="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["status"])' <<<"${STATUS_JSON}")"
  if [[ "${STATUS}" == "completed" ]]; then
    break
  fi
  sleep 0.1
done

log "4. Retrieve submission status (GET /v1/submissions/${SUB_ID})"
printf '%s\n' "${STATUS_JSON}"

log "5. Retrieve Aggregate Report (GET /v1/submissions/${SUB_ID}/aggregate-report)"
curl -fsS "${DEMO_URL}/v1/submissions/${SUB_ID}/aggregate-report"
printf '\n'

log "6. Retrieve Policy Report (GET /v1/submissions/${SUB_ID}/policy-report)"
curl -fsS "${DEMO_URL}/v1/submissions/${SUB_ID}/policy-report"
printf '\n'

log "7. Demonstrate validation failure on invalid PURL (HTTP 422)"
HTTP_CODE="$(curl -sS -o /tmp/scintx-demo-err.json -w '%{http_code}' \
  -X POST "${DEMO_URL}/v1/submissions" \
  -H 'Content-Type: application/json' \
  -d '{"artifact":{"purl":"invalid-purl"}}')"
cat /tmp/scintx-demo-err.json
printf '\n'
if [[ "${HTTP_CODE}" != "422" ]]; then
  die "expected HTTP 422 on invalid PURL, got ${HTTP_CODE}"
fi

log "demo completed successfully"
