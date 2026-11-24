/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Lease

/-!
# The lease theorems

With no fast clock (`cfg.clockAhead = 0`). Lost answers and late renewals
are allowed:

* at most one worker holds a lease that has not run out, and
* a worker that holds such a lease is never refused by the store.
-/

namespace LeaseProof

/-- **Every action keeps the lease fact**, when no clock runs ahead. -/
theorem LeaseInv.step {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (hi : Inv cfg s) (h : LeaseInv s) (a : Action) : LeaseInv (step cfg s a) := by
  -- With `clockAhead = 0`, a clock value `t` is never later than the true time.
  have past : ∀ {t : Nat}, t ≤ s.now + cfg.clockAhead → t ≤ s.now :=
    fun ht => by rw [hc] at ht; exact ht
  have busy : ∀ {w : Nat} {p : Phase}, (s.workers w).phase = p → p ≠ .idle →
      (s.workers w).phase ≠ .idle := fun hp hne => by rw [hp]; exact hne
  cases a with
  | tick d =>
    exact h.frame _ rfl (Nat.le_add_right _ _) (fun v hv => ⟨hv, rfl, rfl⟩)
  | claim w t =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · exact h
      · next r heq =>
        obtain ⟨_, hexp, rfl⟩ := Store.claim_eq_exhausted heq
        exact h.exhausted t (past hg.2) hexp
      · next r heq =>
        obtain ⟨_, hexp, _, rfl⟩ := Store.claim_eq_claimed heq
        exact h.claimed w t _ (past hg.2) hexp
    · exact h
  | renew w t =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨hrun, hown, rfl⟩ := Store.renew_eq_some heq
        exact h.renewed hi w t _ hg.1 hown hrun
      · exact h.drop w
    · exact h
  | complete w =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, hown, rfl⟩ := Store.putCompleted_eq_some heq
        exact h.owner_done hi w _ _ (busy hg (by decide)) hown (by decide)
      · exact h.drop w
    · exact h
  | fail w =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, hown, rfl⟩ := Store.putFailed_eq_some heq
        exact h.owner_done hi w _ _ (busy hg (by decide)) hown (by decide)
      · exact h.drop w
    · exact h
  | retry w t delay =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, hown, rfl⟩ := Store.delayRetry_eq_some heq
        exact h.owner_done hi w _ _ (busy hg.1 (by decide)) hown (by decide)
      · exact h.drop w
    · exact h
  | interruptSave w =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, hown, rfl⟩ := Store.putRunning_eq_some heq
        -- The worker moves on to `releasing`, so it is no longer executing.
        exact h.owner_done hi w _ _ (busy hg (by decide)) hown (fun hp => by cases hp)
      · exact h.drop w
    · exact h
  | interruptSkip w =>
    simp only [LeaseProof.step]
    split
    · -- The worker stops executing. The row is untouched.
      refine h.frame _ ?_ ?_ ?_
      · rfl
      · exact Nat.le_refl _
      · intro v hv
        simp only [setWorker] at hv ⊢
        split at hv
        · cases hv
        · next hne => simp [hne, hv]
    · exact h
  | interruptRelease w =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, hown, rfl⟩ := Store.release_eq_some heq
        exact h.owner_done hi w _ _ (busy hg (by decide)) hown (by decide)
      · exact h.drop w
    · exact h
  | abandon w => exact h.drop w
  | lateRenew k t =>
    -- A late renewal only moves the lease forward, so nothing breaks.
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.renew_eq_some heq
        exact h.lease_extended _
      · exact h
    · exact h

/-- The lease fact holds in every reachable state, when no clock runs ahead. -/
theorem Reachable.leaseInv {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : Reachable cfg s) : LeaseInv s := by
  induction h with
  | init => exact LeaseInv.init
  | step a hs ih => exact ih.step hc hs.inv a

/-- **A worker with an unexpired lease owns the newest attempt.**

If a worker's own deadline has not passed, then its token is the current
attempt number and the row is still running. Nobody took the row away. -/
theorem lease_holder_is_owner {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : Reachable cfg s) (w : Nat) (hw : holdsLease s w) :
    (s.workers w).token = s.row.attempts ∧ s.row.status = .running := by
  rcases h.leaseInv hc w hw.1 with ⟨htok, hrun, _⟩ | hd
  · exact ⟨htok, hrun⟩
  · exact absurd hw.2 (Nat.not_lt_of_le hd)

/-- **At most one worker holds an unexpired lease.**

This is mutual exclusion in the only form a lease can give: two workers
never both believe, at the same moment, that the row is theirs. -/
theorem one_lease_holder {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : Reachable cfg s) (w v : Nat)
    (hw : holdsLease s w) (hv : holdsLease s v) : w = v := by
  have hwb : (s.workers w).phase ≠ .idle := by rw [hw.1]; decide
  have hvb : (s.workers v).phase ≠ .idle := by rw [hv.1]; decide
  have hwt := (lease_holder_is_owner hc h w hw).1
  have hvt := (lease_holder_is_owner hc h v hv).1
  exact Classical.byContradiction fun hne =>
    h.inv.token_unique w v hne hwb hvb (hwt.trans hvt.symm)

/-- **A worker with an unexpired lease can always save its result.**

Work that finishes in time is never thrown away: the store accepts the
"completed" write. -/
theorem lease_holder_can_complete {cfg : Config} {s : State} (hc : cfg.clockAhead = 0)
    (h : Reachable cfg s) (w : Nat) (hw : holdsLease s w) :
    (step cfg s (.complete w)).row.status = .completed := by
  obtain ⟨htok, hrun⟩ := lease_holder_is_owner hc h w hw
  simp [step, hw.1, Store.putCompleted, hrun, htok]

end LeaseProof
