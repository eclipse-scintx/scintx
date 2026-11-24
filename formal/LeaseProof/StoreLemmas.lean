/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Store

/-!
# What each store operation means, as facts the proofs can use

Each lemma reads: "if the operation was accepted, then the guard was true,
and the new row is exactly this". The proofs never open the definitions in
`Store.lean` again. They only use these lemmas.
-/

namespace LeaseProof

/-- A lease that exists is expired exactly when it ended at or before `now`. -/
theorem leaseExpired_some {l now : Nat} : leaseExpired (some l) now = true ↔ l ≤ now := by
  simp [leaseExpired]

/-- An extended lease is never earlier than the new one. -/
theorem le_extendLease_new {lease : Option Nat} {new : Nat} : new ≤ extendLease lease new := by
  cases lease with
  | none => exact Nat.le_refl _
  | some l => exact Nat.le_max_right l new

/-- An extended lease is never earlier than the stored one. -/
theorem le_extendLease_old {lease : Option Nat} {l new : Nat} (h : lease = some l) :
    l ≤ extendLease lease new := by
  subst h
  exact Nat.le_max_left l new

/-- If the stored lease is within one of two limits, and the new lease is
within the first, then the extended lease is within one of them too. -/
theorem extendLease_bound {lease : Option Nat} {new b1 b2 : Nat}
    (hold : ∀ l, lease = some l → l ≤ b1 ∨ l ≤ b2) (hnew : new ≤ b1) :
    extendLease lease new ≤ b1 ∨ extendLease lease new ≤ b2 := by
  cases lease with
  | none => exact Or.inl hnew
  | some l =>
    rcases hold l rfl with h1 | h2
    · exact Or.inl (Nat.max_le.mpr ⟨h1, hnew⟩)
    · -- The stored lease is within `b2`. Use whichever limit is larger.
      rcases Nat.le_total b1 b2 with h12 | h21
      · exact Or.inr (Nat.max_le.mpr ⟨h2, Nat.le_trans hnew h12⟩)
      · exact Or.inl (Nat.max_le.mpr ⟨Nat.le_trans h2 h21, hnew⟩)

/-- An accepted renewal: the row was running, the token matched, and only
the lease changed. The lease only moved forward. -/
theorem Store.renew_eq_some {r r' : Row} {a t d : Nat} (h : Store.renew r a t d = some r') :
    r.status = .running ∧ r.attempts = a ∧
      r' = { r with lease := some (extendLease r.lease (t + d)) } := by
  unfold Store.renew at h
  split at h
  · next hg => exact ⟨hg.1, hg.2, (Option.some.inj h).symm⟩
  · cases h

/-- An accepted retry delay: the row was running, the token matched, and
the lease was set to `t + d`. -/
theorem Store.delayRetry_eq_some {r r' : Row} {a t d : Nat}
    (h : Store.delayRetry r a t d = some r') :
    r.status = .running ∧ r.attempts = a ∧ r' = { r with lease := some (t + d) } := by
  unfold Store.delayRetry at h
  split at h
  · next hg => exact ⟨hg.1, hg.2, (Option.some.inj h).symm⟩
  · cases h

/-- An accepted release: the row was running, the token matched, and only
the lease was cleared. -/
theorem Store.release_eq_some {r r' : Row} {a : Nat} (h : Store.release r a = some r') :
    r.status = .running ∧ r.attempts = a ∧ r' = { r with lease := none } := by
  unfold Store.release at h
  split at h
  · next hg => exact ⟨hg.1, hg.2, (Option.some.inj h).symm⟩
  · cases h

/-- An accepted "completed" write. -/
theorem Store.putCompleted_eq_some {r r' : Row} {a : Nat} (h : Store.putCompleted r a = some r') :
    r.status = .running ∧ r.attempts = a ∧
      r' = { r with status := .completed, lease := none } := by
  unfold Store.putCompleted at h
  split at h
  · next hg => exact ⟨hg.1, hg.2, (Option.some.inj h).symm⟩
  · cases h

/-- An accepted "failed" write. -/
theorem Store.putFailed_eq_some {r r' : Row} {a : Nat} (h : Store.putFailed r a = some r') :
    (r.status = .accepted ∨ r.status = .running) ∧ r.attempts = a ∧
      r' = { r with status := .failed, lease := none } := by
  unfold Store.putFailed at h
  split at h
  · next hg => exact ⟨hg.1, hg.2, (Option.some.inj h).symm⟩
  · cases h

/-- An accepted "running" write (saving an interruption). -/
theorem Store.putRunning_eq_some {r r' : Row} {a i : Nat} (h : Store.putRunning r a i = some r') :
    (r.status = .accepted ∨ r.status = .running) ∧ r.attempts = a ∧
      r' = { r with status := .running, interruptions := i } := by
  unfold Store.putRunning at h
  split at h
  · next hg => exact ⟨hg.1, hg.2, (Option.some.inj h).symm⟩
  · cases h

/-- A successful claim: the row was open, its lease was expired, and there
was budget left. The attempt counter went up by one. -/
theorem Store.claim_eq_claimed {m : Nat} {r r' : Row} {t d : Nat}
    (h : Store.claim m r t d = .claimed r') :
    (r.status = .accepted ∨ r.status = .running) ∧ leaseExpired r.lease t = true ∧
      r.attempts - r.interruptions < m ∧
      r' = { r with status := .running, attempts := r.attempts + 1, lease := some (t + d) } := by
  unfold Store.claim at h
  split at h
  · next hg =>
    split at h
    · cases h
    · next hx => exact ⟨hg.1, hg.2, Nat.lt_of_not_le hx, (ClaimOutcome.claimed.inj h).symm⟩
  · cases h

/-- A claim that found the budget used up: the row was open, its lease was
expired, and the row became `failed`. The attempt counter did not change. -/
theorem Store.claim_eq_exhausted {m : Nat} {r r' : Row} {t d : Nat}
    (h : Store.claim m r t d = .exhausted r') :
    (r.status = .accepted ∨ r.status = .running) ∧ leaseExpired r.lease t = true ∧
      r' = { r with status := .failed, lease := none } := by
  unfold Store.claim at h
  split at h
  · next hg =>
    split at h
    · exact ⟨hg.1, hg.2, (ClaimOutcome.exhausted.inj h).symm⟩
    · cases h
  · cases h

end LeaseProof
