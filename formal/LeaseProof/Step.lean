/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.StepCases

/-!
# Every action keeps the invariant

Most actions are covered by the general rule `Inv.frame`. The actions that
hand out or change numbers use the lemmas in `StepCases.lean`.
-/

namespace LeaseProof

/-- **Every action keeps the invariant.** -/
theorem Inv.step {cfg : Config} {s : State} (h : Inv cfg s) (a : Action) :
    Inv cfg (step cfg s a) := by
  -- Used when an action only makes worker `w` idle and leaves the row alone.
  have drop : ∀ w, Inv cfg { s with workers := setWorker s.workers w Worker.idle } :=
    fun w => h.frame _ rfl rfl h.accepted_fresh h.terminal_no_lease (idle_keeps_tokens s w)
  cases a with
  | tick d =>
    exact h.frame _ rfl rfl h.accepted_fresh h.terminal_no_lease
      (fun v hv => ⟨hv, rfl, rfl, id⟩)
  | claim w t =>
    simp only [LeaseProof.step]
    split
    · split
      · exact h
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.claim_eq_exhausted heq
        exact h.frame _ rfl rfl (fun hc => by cases hc) (fun _ => rfl)
          (fun v hv => ⟨hv, rfl, rfl, id⟩)
      · next r heq =>
        obtain ⟨_, _, hbud, rfl⟩ := Store.claim_eq_claimed heq
        exact h.claimed w t hbud
    · exact h
  | renew w t =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨hrun, _, rfl⟩ := Store.renew_eq_some heq
        exact h.frame _ rfl rfl (fun hc => by simp [hrun] at hc)
          (fun hc => by simp [hrun, Status.isTerminal] at hc)
          (update_keeps_tokens s w _ (by rw [hg.1]; decide) rfl rfl (fun _ => hg.1))
      · exact drop w
    · exact h
  | complete w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.putCompleted_eq_some heq
        exact h.frame _ rfl rfl (fun hc => by cases hc) (fun _ => rfl) (idle_keeps_tokens s w)
      · exact drop w
    · exact h
  | fail w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨_, _, rfl⟩ := Store.putFailed_eq_some heq
        exact h.frame _ rfl rfl (fun hc => by cases hc) (fun _ => rfl) (idle_keeps_tokens s w)
      · exact drop w
    · exact h
  | retry w t delay =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨hrun, _, rfl⟩ := Store.delayRetry_eq_some heq
        exact h.frame _ rfl rfl (fun hc => by simp [hrun] at hc)
          (fun hc => by simp [hrun, Status.isTerminal] at hc) (idle_keeps_tokens s w)
      · exact drop w
    · exact h
  | interruptSave w =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      split
      · next r heq =>
        obtain ⟨_, hown, rfl⟩ := Store.putRunning_eq_some heq
        exact h.interrupted w hg hown
      · exact drop w
    · exact h
  | interruptSkip w =>
    simp only [LeaseProof.step]
    split
    · next hg =>
      exact h.frame _ rfl rfl h.accepted_fresh h.terminal_no_lease
        (update_keeps_tokens s w _ (by rw [hg]; decide) rfl rfl (fun hc => by cases hc))
    · exact h
  | interruptRelease w =>
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨hrun, _, rfl⟩ := Store.release_eq_some heq
        exact h.frame _ rfl rfl (fun hc => by simp [hrun] at hc)
          (fun hc => by simp [hrun, Status.isTerminal] at hc) (idle_keeps_tokens s w)
      · exact drop w
    · exact h
  | abandon w => exact drop w
  | lateRenew k t =>
    -- Only the lease changes. No worker learns about it.
    simp only [LeaseProof.step]
    split
    · split
      · next r heq =>
        obtain ⟨hrun, _, rfl⟩ := Store.renew_eq_some heq
        exact h.lease_changed _ hrun
      · exact h
    · exact h

/-- **The invariant holds in every reachable state.** -/
theorem Reachable.inv {cfg : Config} {s : State} (h : Reachable cfg s) : Inv cfg s := by
  induction h with
  | init => exact Inv.init cfg
  | step a _ ih => exact ih.step a

end LeaseProof
