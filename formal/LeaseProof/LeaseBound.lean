/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Reachable
import LeaseProof.StoreLemmas

/-!
# A lease never reaches far into the future

Every lease in the database ends within one lease duration, or within one
retry delay, of the true time. So a worker that crashes blocks its row for
a bounded time only. `Progress.lean` builds on this.

This needs `cfg.clockAhead = 0`: a gateway with a fast clock could write a
lease that ends later. A late renewal is no problem: it carries an old
clock value, so the lease it asks for ends even sooner.
-/

namespace LeaseProof

/-- A lease ends within one lease duration, or within one retry delay. -/
def LeaseBound (cfg : Config) (s : State) : Prop :=
  ∀ l, s.row.lease = some l →
    l ≤ s.now + cfg.leaseDuration ∨ l ≤ s.now + cfg.maxRetryDelay

/-- A state with no lease is within the bound. -/
theorem LeaseBound.no_lease {cfg : Config} {s : State} (h : s.row.lease = none) :
    LeaseBound cfg s := by
  intro l hl
  rw [h] at hl
  cases hl

/-- A lease of one lease duration, written with a clock value `t` that is
not ahead of the true time, is within the bound. -/
theorem LeaseBound.fresh_lease {cfg : Config} {s : State} {t : Nat} (ht : t ≤ s.now)
    (h : s.row.lease = some (t + cfg.leaseDuration)) : LeaseBound cfg s := by
  intro l hl
  rw [h] at hl
  have := Option.some.inj hl
  exact Or.inl (by omega)

/-- A renewal keeps the bound. The new lease is the later of the stored
lease (within the bound already) and `t + leaseDuration` (within the bound
because `t` is not ahead of the true time). -/
theorem LeaseBound.extended_lease {cfg : Config} {s s' : State} (h : LeaseBound cfg s)
    {t : Nat} (ht : t ≤ s.now) (hnow : s'.now = s.now)
    (hl : s'.row.lease = some (extendLease s.row.lease (t + cfg.leaseDuration))) :
    LeaseBound cfg s' := by
  intro l hl'
  rw [hl] at hl'
  rw [← Option.some.inj hl', hnow]
  exact extendLease_bound h (Nat.add_le_add_right ht _)

/-- Every action keeps the lease bound, when no clock runs ahead. -/
theorem LeaseBound.step {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : LeaseBound cfg s) (a : Action) : LeaseBound cfg (step cfg s a) := by
  have past : ∀ {t : Nat}, t ≤ s.now + cfg.clockAhead → t ≤ s.now :=
    fun ht => by rw [hc] at ht; exact ht
  cases a with
  | tick d =>
    -- Time moves on. The lease does not. So the bound only gets easier.
    intro l hl
    rcases h l hl with h1 | h2
    · exact Or.inl (Nat.le_trans h1 (by show s.now + _ ≤ s.now + d + _; omega))
    · exact Or.inr (Nat.le_trans h2 (by show s.now + _ ≤ s.now + d + _; omega))
  | claim w t =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · exact h
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.claim_eq_exhausted heq
        exact LeaseBound.no_lease rfl
      · next r heq =>
        obtain ⟨_, _, _, rfl⟩ := Store.claim_eq_claimed heq
        exact LeaseBound.fresh_lease (past hg.2) rfl
    · exact h
  | renew w t =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.renew_eq_some heq
        exact h.extended_lease (past hg.2) rfl rfl
      · exact h
    · exact h
  | complete w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.putCompleted_eq_some heq
        exact LeaseBound.no_lease rfl
      · exact h
    · exact h
  | fail w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.putFailed_eq_some heq
        exact LeaseBound.no_lease rfl
      · exact h
    · exact h
  | retry w t delay =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        -- The lease is now `t + delay`, and the delay has an upper limit.
        obtain ⟨_, _, rfl⟩ := Store.delayRetry_eq_some heq
        intro l hl
        have hl' : t + delay = l := Option.some.inj hl
        have ht := past hg.2.1
        have hd := hg.2.2
        exact Or.inr (by show l ≤ s.now + cfg.maxRetryDelay; omega)
      · exact h
    · exact h
  | interruptSave w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.putRunning_eq_some heq
        exact h
      · exact h
    · exact h
  | interruptSkip w =>
    simp only [LeaseProof.step]
    split <;> exact h
  | interruptRelease w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.release_eq_some heq
        exact LeaseBound.no_lease rfl
      · exact h
    · exact h
  | abandon w => exact h
  | lateRenew k t =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.renew_eq_some heq
        exact h.extended_lease (past hg) rfl rfl
      · exact h
    · exact h

/-- **A lease is never longer than one lease duration or one retry delay.**

So a worker that crashes blocks its row for a bounded time only. -/
theorem lease_is_bounded {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : Reachable cfg s) : LeaseBound cfg s := by
  induction h with
  | init => exact LeaseBound.no_lease rfl
  | step a _ ih => exact ih.step hc a

end LeaseProof
