/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Model

/-!
# A busy worker never gets a new token

A token is given out by a claim, and only an idle worker claims. So a
worker's token is fixed for the whole attempt. `fenced_stays` in
`Safety.lean` is built on this. Split out of `Effects.lean` to keep each
file small.
-/

namespace LeaseProof

/-- Making a worker idle: any worker is then idle or has its old token. -/
theorem setWorker_idle (ws : Nat → Worker) (w v : Nat) :
    (setWorker ws w Worker.idle v).phase = .idle ∨
      (setWorker ws w Worker.idle v).token = (ws v).token := by
  unfold setWorker
  split
  · exact Or.inl rfl
  · exact Or.inr rfl

/-- Updating a worker without changing its token keeps every token. -/
theorem setWorker_token (ws : Nat → Worker) (w v : Nat) (x : Worker)
    (hx : x.token = (ws w).token) : (setWorker ws w x v).token = (ws v).token := by
  unfold setWorker
  split
  · next heq => subst heq; exact hx
  · rfl

/-- **A busy worker never gets a new token.**

After any action, a worker that was busy is either idle or still has the
token it had. A new token is only ever given to an idle worker. -/
theorem busy_keeps_token (cfg : Config) (s : State) (a : Action) (v : Nat)
    (hb : (s.workers v).phase ≠ .idle) :
    ((step cfg s a).workers v).phase = .idle ∨
      ((step cfg s a).workers v).token = (s.workers v).token := by
  cases a with
  | tick d => exact Or.inr rfl
  | claim w t =>
    simp only [step]
    split
    · next hg =>
      split
      · exact Or.inr rfl
      · exact Or.inr rfl
      · -- The claiming worker `w` was idle, so it is not the busy worker `v`.
        simp only [setWorker]
        split
        · next heq => subst heq; exact absurd hg.1 hb
        · exact Or.inr rfl
    · exact Or.inr rfl
  | renew w t =>
    simp only [step]
    split
    · split
      · exact Or.inr (setWorker_token _ _ _ _ rfl)
      · exact setWorker_idle _ _ _
    · exact Or.inr rfl
  | complete w =>
    simp only [step]
    split
    · split <;> exact setWorker_idle _ _ _
    · exact Or.inr rfl
  | fail w =>
    simp only [step]
    split
    · split <;> exact setWorker_idle _ _ _
    · exact Or.inr rfl
  | retry w t delay =>
    simp only [step]
    split
    · split <;> exact setWorker_idle _ _ _
    · exact Or.inr rfl
  | interruptSave w =>
    simp only [step]
    split
    · split
      · exact Or.inr (setWorker_token _ _ _ _ rfl)
      · exact setWorker_idle _ _ _
    · exact Or.inr rfl
  | interruptSkip w =>
    simp only [step]
    split
    · exact Or.inr (setWorker_token _ _ _ _ rfl)
    · exact Or.inr rfl
  | interruptRelease w =>
    simp only [step]
    split
    · split <;> exact setWorker_idle _ _ _
    · exact Or.inr rfl
  | abandon w => exact setWorker_idle _ _ _
  -- A late renewal changes the row only. No worker changes.
  | lateRenew k t =>
    simp only [step]
    split
    · split <;> exact Or.inr rfl
    · exact Or.inr rfl

end LeaseProof
