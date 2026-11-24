/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.LeaseBound

/-!
# Self-healing: a row cannot stay blocked

The README promises that a crash never leaves a scan stuck. This file proves
the part of that promise that is about the lease:

* a lease never reaches further into the future than one lease duration, or
  one retry delay (`lease_is_bounded` in `LeaseBound.lean`), and so
* after waiting that long, ANY idle worker can claim an unfinished row.

This needs `cfg.clockAhead = 0`. It holds even when writes land late.

What is NOT proven here is that a worker actually does come along. That
needs a running gateway, which no proof can promise.
-/

namespace LeaseProof

/-- **Self-healing: after waiting, any idle worker can claim the row.**

Take any reachable state with an unfinished row. It does not matter what
went wrong before: crashes, lost leases, failed writes. Wait `d`, where `d`
is at least the lease duration and the longest retry delay. Then a claim by
any idle worker takes effect. Either it starts a new attempt, or the
attempt budget is used up and the row becomes `failed`.

Each new attempt adds one to `attempts`, and `attempt_budget` limits how
often that can happen. So a row cannot be retried forever either. -/
theorem never_stuck {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : Reachable cfg s) (w d : Nat)
    (hopen : s.row.status.isTerminal = false)
    (hidle : (s.workers w).phase = .idle)
    (hL : cfg.leaseDuration ≤ d) (hD : cfg.maxRetryDelay ≤ d) :
    (step cfg (step cfg s (.tick d)) (.claim w (s.now + d))).row.attempts = s.row.attempts + 1 ∨
      (step cfg (step cfg s (.tick d)) (.claim w (s.now + d))).row.status = .failed := by
  -- The row is unfinished, so it is `accepted` or `running`.
  have hst : s.row.status = .accepted ∨ s.row.status = .running := by
    cases hs : s.row.status <;> simp [hs, Status.isTerminal] at hopen ⊢
  -- After waiting `d`, whatever lease there was has run out.
  have hexp : leaseExpired s.row.lease (s.now + d) = true := by
    cases hl : s.row.lease with
    | none => rfl
    | some l =>
      have := lease_is_bounded hc h l hl
      exact leaseExpired_some.mpr (by omega)
  -- So the claim goes through. Which of the two results we get depends only
  -- on whether the attempt budget is used up.
  by_cases hex : cfg.maxAttempts ≤ s.row.attempts - s.row.interruptions
  · exact Or.inr (by simp [step, hidle, Store.claim, hst, hexp, hex])
  · exact Or.inl (by simp [step, hidle, Store.claim, hst, hexp, hex])

end LeaseProof
