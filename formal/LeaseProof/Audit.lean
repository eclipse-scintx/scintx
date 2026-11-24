/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Safety
import LeaseProof.LeaseSafety
import LeaseProof.Progress
import LeaseProof.Limits

/-!
# Audit: what do the proofs rest on?

`#print axioms` lists every axiom that a theorem depends on. The build
prints this list for each main theorem, and `scripts/formal.sh` checks it.

The only axioms allowed are the three standard ones of Lean:
`propext`, `Classical.choice` and `Quot.sound`.

The one that must NEVER show up is `sorryAx`. It appears when a proof has a
hole (`sorry`). A theorem that depends on `sorryAx` is not proven.
-/

namespace LeaseProof

-- Hold with any clocks and any network (`Safety.lean`).
#print axioms Reachable.inv
#print axioms attempts_monotone
#print axioms terminal_is_final
#print axioms fencing
#print axioms late_renewal_is_fenced
#print axioms late_renewal_never_shortens
#print axioms fenced_stays
#print axioms tokens_unique
#print axioms at_most_one_writer
#print axioms attempt_budget

-- Need `clockAhead = 0` (`LeaseSafety.lean`, `LeaseBound.lean`,
-- `Progress.lean`).
#print axioms lease_holder_is_owner
#print axioms one_lease_holder
#print axioms lease_holder_can_complete
#print axioms lease_is_bounded
#print axioms never_stuck

-- The limits (`Limits.lean`).
#print axioms two_workers_can_run_at_once
#print axioms late_result_is_refused
#print axioms clock_skew_allows_two_lease_holders
#print axioms late_renewal_no_longer_breaks_the_lease

end LeaseProof
