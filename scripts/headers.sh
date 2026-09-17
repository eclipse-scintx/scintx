#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Verify every non-excluded Go file and scripts/*.sh carries an EPL-2.0
# SPDX-License-Identifier header.
# Usage: ./scripts/headers.sh
#
# Exclusions live in scripts/license-exclusions.txt (one path per line,
# with a reason after a '#').

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

EXCLUSIONS="${SCRIPTS_DIR}/license-exclusions.txt"

excluded() {
  local path="${1#./}"
  grep -Eq "^[[:space:]]*${path//./\\.}[[:space:]]*(#.*)?$" "${EXCLUSIONS}"
}

fail=0

# Go sources (build-tag files carry the tag on line 1, so scan the first 5 lines).
while IFS= read -r f; do
  if excluded "${f}"; then
    continue
  fi
  if ! awk 'NR<=5 && /^\/\/ SPDX-License-Identifier: EPL-2\.0$/ {found=1} END {exit !found}' "$f"; then
    printf 'missing SPDX header: %s\n' "$f" >&2
    fail=1
  fi
done < <(find . -name '*.go' ! -path './.git/*' | sort)

# Shell scripts in scripts/.
while IFS= read -r f; do
  if excluded "${f}"; then
    continue
  fi
  if ! grep -q '^# SPDX-License-Identifier: EPL-2\.0$' "$f"; then
    printf 'missing SPDX header: %s\n' "$f" >&2
    fail=1
  fi
done < <(find scripts -name '*.sh' | sort)

(( fail )) && die "license header check failed; see files above"
log "headers ok"