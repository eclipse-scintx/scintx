#!/usr/bin/env bash
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Check the formal proofs of the lease architecture (the Lean project in
# formal/). It does two things:
#
#   1. It builds the project. Lean only builds a proof that is correct, so a
#      successful build means every theorem is proven.
#   2. It audits the main theorems. A proof with a hole ("sorry") still
#      builds, but then depends on the axiom "sorryAx". This step fails if
#      any main theorem depends on anything but Lean's three standard axioms.
#   3. It lets the model print the lease test vectors, and writes them to
#      internal/gateway/testdata/lease_vectors.json. The Go tests replay
#      them against the real stores.
#   4. It runs the Go worker trace test: the real workers are run, their
#      store calls are recorded, and the model judges the recording.
#
# Usage: ./scripts/formal.sh
#        CHECK_GENERATED=1 ./scripts/formal.sh   (CI: fail if the vectors
#                                                 file is out of date)
#
# Needs Go (for step 4) and Lean 4. Install Lean with elan: https://lean-lang.org/install/
# The exact Lean version is pinned in formal/lean-toolchain.

set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

# elan puts "lake" here. A shell opened before the install does not have
# this folder on its PATH yet, so add it to be safe.
export PATH="${HOME}/.elan/bin:${PATH}"
command -v lake >/dev/null 2>&1 || die "lake not found; install Lean 4 with elan (https://lean-lang.org/install/)"

cd "${REPO_ROOT}/formal"

log "building the lease proofs"
lake build

log "auditing the axioms of the main theorems"
# Run the audit file directly. A cached build would not print its output.
audit="$(lake env lean LeaseProof/Audit.lean)"
printf '%s\n' "${audit}"

# The audit must have printed something, or this check would pass on nothing.
printf '%s\n' "${audit}" | grep -q "LeaseProof\." || die "the audit printed no theorems"

# First a blunt check: "sorryAx" must not appear anywhere in the audit. This
# does not depend on how the output is laid out, so it cannot be fooled.
if printf '%s\n' "${audit}" | grep -q "sorryAx"; then
  die "a theorem depends on the axiom 'sorryAx'; a proof has a hole (sorry)"
fi

# Lean breaks a long axiom list over several lines, like this:
#
#   'LeaseProof.some_long_name' depends on axioms: [propext,
#    Classical.choice,
#    Quot.sound]
#
# The old code read each line by itself, so it found no "[...]" in a wrapped
# list and skipped that theorem without a word. A theorem with a long name
# could then depend on any axiom and still pass. So join all lines into one
# first. "tr" also drops the carriage returns that Windows adds.
flat="$(printf '%s\n' "${audit}" | tr '\r\n' '  ')"

# Every audited theorem must give an answer that this script understands:
# either a list of axioms, or "does not depend on any axioms". Count the
# "#print axioms" lines in the audit file and compare. If a future Lean
# prints something else, the counts differ and the script stops. Passing
# then would be a guess. ("grep -o" prints one match per line.)
asked="$(grep -c '^#print axioms ' LeaseProof/Audit.lean || true)"
with_list="$(printf '%s\n' "${flat}" | grep -o 'depends on axioms: *\[[^]]*\]' | wc -l | tr -d '[:space:]' || true)"
without="$(printf '%s\n' "${flat}" | grep -o 'does not depend on any axioms' | wc -l | tr -d '[:space:]' || true)"
answered=$((with_list + without))
[[ "${asked}" -gt 0 && "${asked}" == "${answered}" ]] ||
  die "the audit asked about ${asked} theorems but only ${answered} answers could be read"

# Collect every axiom name from the "[a, b, c]" lists, one per line.
# "[^]]*" stops at the first "]". On the joined line a plain ".*" would run
# on to the last "]" and swallow the text between two lists.
axioms="$(printf '%s\n' "${flat}" | grep -o '\[[^]]*\]' | tr -d '[] ' | tr ',' '\n' | sort -u || true)"
for axiom in ${axioms}; do
  case "${axiom}" in
    propext | Classical.choice | Quot.sound) ;; # Lean's standard axioms.
    *) die "a theorem depends on the axiom '${axiom}'; it is not fully proven" ;;
  esac
done

log "printing the lease test vectors"
# The model prints scenarios: store calls, and the row it expects after each
# call. The Go tests replay them against the real stores (see
# internal/gateway/lease_vectors_test.go). This is what ties the proofs to
# the code, so the file must always match the model.
vectors="${REPO_ROOT}/internal/gateway/testdata/lease_vectors.json"
fresh="$(lake env lean --run LeaseProof/Vectors.lean)"
[[ -n "${fresh}" ]] || die "the model printed no test vectors"

if [[ "${CHECK_GENERATED:-0}" == "1" ]]; then
  # CI mode: change nothing, only compare. A difference means that someone
  # changed the model (or the file) without running this script.
  # "tr" drops carriage returns, which git may add to the file on Windows.
  if [[ "${fresh}" != "$(tr -d '\r' <"${vectors}")" ]]; then
    die "lease_vectors.json does not match the model; run ./scripts/formal.sh and commit the result"
  fi
else
  printf '%s\n' "${fresh}" >"${vectors}"
fi

log "judging runs of the real workers against the model"
# The Go test runs the real worker code through many situations, records
# every store call, and lets the Lean model judge the recording (see
# internal/gateway/trace_test.go). SCINTX_REQUIRE_LEAN=1 makes the test fail
# instead of skip if it cannot find Lean.
command -v go >/dev/null 2>&1 || die "go not found; the worker trace check needs it"
(cd "${REPO_ROOT}" && SCINTX_REQUIRE_LEAN=1 go test ./internal/gateway/ -count=1 -run 'TestWorkerTracesFollowTheModel')

log "lease proofs ok"
