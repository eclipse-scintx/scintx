#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Deterministic offline demonstration of the Eclipse SCINTX gateway:
#   1. Builds the gateway binary
#   2. Starts the gateway backed by a persistent SQLite database
#   3. Verifies liveness (/healthz), readiness (/readyz), and CLI health probe
#   4. Submits a valid artifact (POST /v1/submissions)
#   5. Retrieves submission status (GET /v1/submissions/{id})
#   6. Restarts the gateway and verifies submission persistence across restart
#   7. Demonstrates a validation failure (HTTP 422)

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

DEMO_PORT="${SCINTX_DEMO_PORT:-18080}"
DEMO_URL="http://127.0.0.1:${DEMO_PORT}"
DEMO_DB="$(mktemp -u /tmp/scintx-demo-XXXXXX.db)"
GW_PID=""

cleanup() {
  if [[ -n "${GW_PID}" ]]; then
    kill "${GW_PID}" >/dev/null 2>&1 || true
  fi
  rm -f "${DEMO_DB}" "${DEMO_DB}-wal" "${DEMO_DB}-shm" /tmp/scintx-demo-err.json
}
trap cleanup EXIT

start_gateway() {
  SCINTX_ADDR="127.0.0.1:${DEMO_PORT}" \
  SCINTX_DATABASE_URL="file:${DEMO_DB}" \
    "${BINARY}" serve >/tmp/scintx-demo.log 2>&1 &
  GW_PID=$!
  for _ in $(seq 1 30); do
    if SCINTX_ADDR="127.0.0.1:${DEMO_PORT}" "${BINARY}" health >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  die "gateway failed to become ready"
}

"${SCRIPTS_DIR}/build.sh"

log "starting Eclipse SCINTX gateway on :${DEMO_PORT} (db=${DEMO_DB})"
start_gateway

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
  -d '{"artifact":{"purl":"pkg:npm/lodash@4.17.20"}}')"
printf '%s\n' "${SUB_JSON}"

SUB_ID="$(printf '%s' "${SUB_JSON}" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"

# Poll until submission reaches completed status.
for _ in $(seq 1 30); do
  STATUS_JSON="$(curl -fsS "${DEMO_URL}/v1/submissions/${SUB_ID}")"
  STATUS="$(printf '%s' "${STATUS_JSON}" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
  if [[ "${STATUS}" == "completed" ]]; then
    break
  fi
  sleep 0.1
done

log "4. Retrieve submission status (GET /v1/submissions/${SUB_ID})"
printf '%s\n' "${STATUS_JSON}"

log "5. Restart gateway and verify submission persists in SQLite across restart"
kill "${GW_PID}" >/dev/null 2>&1 || true
wait "${GW_PID}" 2>/dev/null || true
start_gateway
curl -fsS "${DEMO_URL}/v1/submissions/${SUB_ID}"
printf '\n'

log "6. Demonstrate validation failure on invalid PURL (HTTP 422)"
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
