#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Build the container image, start it, and wait until it reports "healthy".
# Usage: ./scripts/image-check.sh
#
# Why this script exists: the Go tests and the demo run the gateway as a
# plain program. Nothing built the image. So a broken Dockerfile, a Go
# package missing from .dockerignore, or a health probe that cannot run
# inside the image would only be found by the first person who deployed it.
#
# How it decides: the Dockerfile has a HEALTHCHECK that runs "/scintx health"
# INSIDE the container. The container tool runs it on a timer and records the
# result as "starting", "healthy" or "unhealthy". This script only reads that
# result. So it tests the very probe that the image ships with, and it needs
# no published port, no curl and no shell in the image.
#
# Settings (all optional):
#   SCINTX_CONTAINER_TOOL       the command to use (default: docker).
#                               Podman works too, but it only keeps the
#                               HEALTHCHECK when the image is built in the
#                               Docker format: set BUILDAH_FORMAT=docker.
#   SCINTX_IMAGE_CHECK_IMAGE    the tag for the image (default below).
#   SCINTX_IMAGE_CHECK_TIMEOUT  seconds to wait for "healthy" (default: 90).

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

TOOL="${SCINTX_CONTAINER_TOOL:-docker}"
IMAGE="${SCINTX_IMAGE_CHECK_IMAGE:-scintx-gateway:image-check}"
# The process id makes the name unique, so two runs do not collide.
NAME="scintx-image-check-$$"
# The HEALTHCHECK runs every 15 s and gives up after 3 failures in a row.
# Docker runs the first probe after one interval, so "healthy" comes after
# about 15 s. (Podman probes once at start, so there it comes at once.)
# "unhealthy" comes after about 45 s. 90 s leaves room for a slow machine
# in both cases.
TIMEOUT="${SCINTX_IMAGE_CHECK_TIMEOUT:-90}"

# There is no "skipped" result here (unlike lint.sh). This script is not part
# of check.sh. Whoever runs it wants the image checked, so a missing tool is
# always an error.
command -v "${TOOL}" >/dev/null 2>&1 || die "${TOOL} is not installed; it is needed to build and run the image"

# Always remove the container, also when the check fails. "-v" removes the
# unnamed /data volume with it. The image is kept: it makes the next run fast.
cleanup() {
  "${TOOL}" rm -f -v "${NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Stop with an error, but first show what the container and its health
# probe printed. In CI this output is all there is to find the cause.
fail() {
  log "container log:"
  "${TOOL}" logs "${NAME}" >&2 || true
  log "health probe record:"
  "${TOOL}" inspect --format '{{json .State.Health}}' "${NAME}" >&2 || true
  die "$1"
}

log "image-check: building ${IMAGE} with ${TOOL}"
# lib.sh has already moved to the repository root, so "." is the whole
# repository. .dockerignore decides which part of it the builder gets.
"${TOOL}" build -t "${IMAGE}" .

log "image-check: starting a container from ${IMAGE}"
# No options on purpose: this is the plain "docker run" of the README, with
# the image's own user, config, /data volume and HEALTHCHECK. No port is
# published, because the probe runs inside the container.
"${TOOL}" run -d --name "${NAME}" "${IMAGE}" >/dev/null

log "image-check: waiting up to ${TIMEOUT}s for the HEALTHCHECK to report healthy"
# SECONDS is a bash counter. It counts up by itself once it is set.
SECONDS=0
while (( SECONDS < TIMEOUT )); do
  # One call reads both values: is the container running, and what did the
  # probe say. If the image has no HEALTHCHECK at all, Docker cannot fill in
  # the health part and this call fails. That is wanted: the check must not
  # pass because the probe was deleted.
  status="$("${TOOL}" inspect --format '{{.State.Status}} {{.State.Health.Status}}' "${NAME}")" \
    || fail "cannot read the health state; does the Dockerfile still have a HEALTHCHECK?"
  read -r state health <<<"${status}"

  # A gateway that stopped can never become healthy. Report it at once.
  if [[ "${state}" != "running" ]]; then
    fail "the container is not running (state: ${state:-unknown}); the gateway stopped at startup"
  fi

  case "${health}" in
    healthy)
      log "image-check ok: the container reported healthy after ${SECONDS}s"
      exit 0
      ;;
    unhealthy)
      fail "the HEALTHCHECK reported unhealthy; the gateway runs but /readyz does not answer 200"
      ;;
  esac
  # "starting" (or no answer yet): the probe has not passed so far. Wait.
  sleep 2
done

fail "the container did not report healthy within ${TIMEOUT}s (last health state: ${health:-none})"
