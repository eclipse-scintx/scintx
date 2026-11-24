/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Model

/-!
# What one action can do

One helper lemma. It turns "check every action" into "check the six store
operations". The safety theorems in `Safety.lean` are built on it.
-/

namespace LeaseProof

/-- The worker that performs an action. `tick` has none. -/
def Action.actor : Action → Option Nat
  | .tick _ => none
  | .claim w _ => some w
  | .renew w _ => some w
  | .complete w => some w
  | .fail w => some w
  | .retry w _ _ => some w
  | .interruptSave w => some w
  | .interruptSkip w => some w
  | .interruptRelease w => some w
  | .abandon w => some w
  -- A late renewal arrives by itself. Its sender has moved on.
  | .lateRenew _ _ => none

/-- **The row only changes through a store operation.**

To prove a fact `P` about the row after any action, it is enough to check:

* the row as it was (the action did not touch it),
* the result of each store operation, called by the acting worker `w` with
  its own token, and
* the result of a late renewal, which may carry any token.

A claim is only made by an idle worker. Every other store call is made by a
busy worker. -/
theorem step_row_cases (cfg : Config) (s : State) (a : Action) (P : Row → Prop)
    (same : P s.row)
    (exhausted : ∀ w t r, a.actor = some w → (s.workers w).phase = .idle →
      Store.claim cfg.maxAttempts s.row t cfg.leaseDuration = .exhausted r → P r)
    (claimed : ∀ w t r, a.actor = some w → (s.workers w).phase = .idle →
      Store.claim cfg.maxAttempts s.row t cfg.leaseDuration = .claimed r → P r)
    (renew : ∀ w t d r, a.actor = some w → (s.workers w).phase ≠ .idle →
      Store.renew s.row (s.workers w).token t d = some r → P r)
    (delay : ∀ w t d r, a.actor = some w → (s.workers w).phase ≠ .idle →
      Store.delayRetry s.row (s.workers w).token t d = some r → P r)
    (release : ∀ w r, a.actor = some w → (s.workers w).phase ≠ .idle →
      Store.release s.row (s.workers w).token = some r → P r)
    (completed : ∀ w r, a.actor = some w → (s.workers w).phase ≠ .idle →
      Store.putCompleted s.row (s.workers w).token = some r → P r)
    (failed : ∀ w r, a.actor = some w → (s.workers w).phase ≠ .idle →
      Store.putFailed s.row (s.workers w).token = some r → P r)
    (running : ∀ w i r, a.actor = some w → (s.workers w).phase ≠ .idle →
      Store.putRunning s.row (s.workers w).token i = some r → P r)
    -- A late renewal has no acting worker. It carries any token `k`.
    (late : ∀ k t r, a.actor = none →
      Store.renew s.row k t cfg.leaseDuration = some r → P r) :
    P (step cfg s a).row := by
  -- A worker in phase `p` that is not idle.
  have busy : ∀ {w : Nat} {p : Phase}, (s.workers w).phase = p → p ≠ .idle →
      (s.workers w).phase ≠ .idle := fun hp hne => by rw [hp]; exact hne
  cases a with
  | tick d => exact same
  | claim w t =>
    simp only [step]
    split
    · next hg =>
      split
      · exact same
      · next r heq => exact exhausted w t r rfl hg.1 heq
      · next r heq => exact claimed w t r rfl hg.1 heq
    · exact same
  | renew w t =>
    simp only [step]
    split
    · next hg =>
      split
      · next r heq => exact renew w t _ r rfl (busy hg.1 (by decide)) heq
      · exact same
    · exact same
  | complete w =>
    simp only [step]
    split
    · next hg =>
      split
      · next r heq => exact completed w r rfl (busy hg (by decide)) heq
      · exact same
    · exact same
  | fail w =>
    simp only [step]
    split
    · next hg =>
      split
      · next r heq => exact failed w r rfl (busy hg (by decide)) heq
      · exact same
    · exact same
  | retry w t d =>
    simp only [step]
    split
    · next hg =>
      split
      · next r heq => exact delay w t d r rfl (busy hg.1 (by decide)) heq
      · exact same
    · exact same
  | interruptSave w =>
    simp only [step]
    split
    · next hg =>
      split
      · next r heq => exact running w _ r rfl (busy hg (by decide)) heq
      · exact same
    · exact same
  | interruptSkip w =>
    simp only [step]
    split <;> exact same
  | interruptRelease w =>
    simp only [step]
    split
    · next hg =>
      split
      · next r heq => exact release w r rfl (busy hg (by decide)) heq
      · exact same
    · exact same
  | abandon w => exact same
  | lateRenew k t =>
    simp only [step]
    split
    · split
      · next r heq => exact late k t r rfl heq
      · exact same
    · exact same

-- The lemmas about worker tokens that used to follow here are now in
-- `Tokens.lean`. They were moved to keep this file small.

end LeaseProof
