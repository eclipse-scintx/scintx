/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Step
import LeaseProof.Effects
import LeaseProof.Tokens

/-!
# Safety theorems that do not depend on clocks

These are the guarantees that protect the stored result. None of them
mentions time, and `Config.clockAhead` is unrestricted. So they hold
however wrong the clocks are, however slow the network is, even when
writes arrive late, and whenever workers crash.

In short: **leases decide who should work. Fencing decides who may write.**
The theorems here are about fencing.
-/

namespace LeaseProof

/-- **The attempt counter never goes down.**

It is the fencing token, so this is what makes an old token stay old. -/
theorem attempts_monotone (cfg : Config) (s : State) (a : Action) :
    s.row.attempts ≤ (step cfg s a).row.attempts := by
  apply step_row_cases cfg s a (fun r => s.row.attempts ≤ r.attempts)
  · exact Nat.le_refl _
  · intro w t r _ _ h; obtain ⟨_, _, rfl⟩ := Store.claim_eq_exhausted h; exact Nat.le_refl _
  · intro w t r _ _ h; obtain ⟨_, _, _, rfl⟩ := Store.claim_eq_claimed h; exact Nat.le_succ _
  · intro w t d r _ _ h; obtain ⟨_, _, rfl⟩ := Store.renew_eq_some h; exact Nat.le_refl _
  · intro w t d r _ _ h; obtain ⟨_, _, rfl⟩ := Store.delayRetry_eq_some h; exact Nat.le_refl _
  · intro w r _ _ h; obtain ⟨_, _, rfl⟩ := Store.release_eq_some h; exact Nat.le_refl _
  · intro w r _ _ h; obtain ⟨_, _, rfl⟩ := Store.putCompleted_eq_some h; exact Nat.le_refl _
  · intro w r _ _ h; obtain ⟨_, _, rfl⟩ := Store.putFailed_eq_some h; exact Nat.le_refl _
  · intro w i r _ _ h; obtain ⟨_, _, rfl⟩ := Store.putRunning_eq_some h; exact Nat.le_refl _
  · intro k t r _ h; obtain ⟨_, _, rfl⟩ := Store.renew_eq_some h; exact Nat.le_refl _

/-- **`completed` and `failed` are final.**

Once a row is finished, no action changes any part of it. A late worker
cannot turn a failure into a success, or a success into a failure. -/
theorem terminal_is_final (cfg : Config) (s : State) (a : Action)
    (h : s.row.status.isTerminal = true) : (step cfg s a).row = s.row := by
  -- A finished row is neither `accepted` nor `running`. Every store
  -- operation needs one of those two, so every operation is refused.
  have hna : s.row.status ≠ .accepted := by intro hc; rw [hc] at h; cases h
  have hnr : s.row.status ≠ .running := by intro hc; rw [hc] at h; cases h
  have hopen : ¬(s.row.status = .accepted ∨ s.row.status = .running) :=
    fun hc => hc.elim hna hnr
  apply step_row_cases cfg s a (fun r => r = s.row)
  · rfl
  · intro w t r _ _ h; exact absurd (Store.claim_eq_exhausted h).1 hopen
  · intro w t r _ _ h; exact absurd (Store.claim_eq_claimed h).1 hopen
  · intro w t d r _ _ h; exact absurd (Store.renew_eq_some h).1 hnr
  · intro w t d r _ _ h; exact absurd (Store.delayRetry_eq_some h).1 hnr
  · intro w r _ _ h; exact absurd (Store.release_eq_some h).1 hnr
  · intro w r _ _ h; exact absurd (Store.putCompleted_eq_some h).1 hnr
  · intro w r _ _ h; exact absurd (Store.putFailed_eq_some h).1 hopen
  · intro w i r _ _ h; exact absurd (Store.putRunning_eq_some h).1 hopen
  · intro k t r _ h; exact absurd (Store.renew_eq_some h).1 hnr

/-- **Fencing: a worker with an old token cannot change the row.**

If a busy worker's token is not the current attempt number, then nothing it
does has any effect on the row. Every one of its writes is refused. -/
theorem fencing (cfg : Config) (s : State) (a : Action) (w : Nat)
    (hactor : a.actor = some w)
    (hbusy : (s.workers w).phase ≠ .idle)
    (hstale : (s.workers w).token ≠ s.row.attempts) :
    (step cfg s a).row = s.row := by
  -- The acting worker `u` in each case below is `w` itself.
  have same : ∀ {u : Nat}, a.actor = some u → u = w :=
    fun hu => Option.some.inj (hu.symm.trans hactor)
  apply step_row_cases cfg s a (fun r => r = s.row)
  · rfl
  · intro u t r hu hidle _; rw [same hu] at hidle; exact absurd hidle hbusy
  · intro u t r hu hidle _; rw [same hu] at hidle; exact absurd hidle hbusy
  · intro u t d r hu _ h; rw [same hu] at h
    exact absurd (Store.renew_eq_some h).2.1.symm hstale
  · intro u t d r hu _ h; rw [same hu] at h
    exact absurd (Store.delayRetry_eq_some h).2.1.symm hstale
  · intro u r hu _ h; rw [same hu] at h
    exact absurd (Store.release_eq_some h).2.1.symm hstale
  · intro u r hu _ h; rw [same hu] at h
    exact absurd (Store.putCompleted_eq_some h).2.1.symm hstale
  · intro u r hu _ h; rw [same hu] at h
    exact absurd (Store.putFailed_eq_some h).2.1.symm hstale
  · intro u i r hu _ h; rw [same hu] at h
    exact absurd (Store.putRunning_eq_some h).2.1.symm hstale
  · -- A late renewal has no acting worker, so it is not `w`'s action.
    intro k t r hnone _; rw [hnone] at hactor; cases hactor

/-- **Fencing also stops late writes.**

A renewal that arrives late with an old attempt number changes nothing. So
a write that was stuck in the network cannot disturb a newer attempt. -/
theorem late_renewal_is_fenced (cfg : Config) (s : State) (k t : Nat)
    (hstale : k ≠ s.row.attempts) : (step cfg s (.lateRenew k t)).row = s.row := by
  simp only [step]
  split
  · split
    · next r heq => exact absurd (Store.renew_eq_some heq).2.1.symm hstale
    · rfl
  · rfl

/-- **A late renewal never moves the lease back.**

Whatever old clock value it carries, the lease afterwards is at least what
it was. This is the fix for the flaw that an earlier version of these
proofs found: an old renewal that landed after a newer one shortened the
lease, and a second worker could then claim the row too early. -/
theorem late_renewal_never_shortens (cfg : Config) (s : State) (k t l : Nat)
    (h : s.row.lease = some l) :
    ∃ l', (step cfg s (.lateRenew k t)).row.lease = some l' ∧ l ≤ l' := by
  simp only [step]
  split
  · split
    · next r heq =>
      obtain ⟨_, _, rfl⟩ := Store.renew_eq_some heq
      exact ⟨_, rfl, le_extendLease_old h⟩
    · exact ⟨l, h, Nat.le_refl _⟩
  · exact ⟨l, h, Nat.le_refl _⟩

/-- A worker is fenced when it is busy with a token older than the row's. -/
def fenced (s : State) (w : Nat) : Prop :=
  (s.workers w).phase ≠ .idle ∧ (s.workers w).token < s.row.attempts

/-- **Once fenced, always fenced.**

A fenced worker stays fenced until it gives up its attempt. Together with
`fencing` this means: after a newer attempt exists, the old worker can never
write again, no matter how long it keeps running. -/
theorem fenced_stays (cfg : Config) (s : State) (a : Action) (w : Nat) (h : fenced s w) :
    ((step cfg s a).workers w).phase = .idle ∨ fenced (step cfg s a) w := by
  have hmono := attempts_monotone cfg s a
  rcases busy_keeps_token cfg s a w h.1 with hidle | htok
  · exact Or.inl hidle
  · by_cases hp : ((step cfg s a).workers w).phase = .idle
    · exact Or.inl hp
    · exact Or.inr ⟨hp, by rw [htok]; exact Nat.lt_of_lt_of_le h.2 hmono⟩

/-- **No two busy workers ever have the same token.**

Each claim hands out a new attempt number, and the store does that
atomically. -/
theorem tokens_unique {cfg : Config} {s : State} (h : Reachable cfg s) (w v : Nat)
    (hw : (s.workers w).phase ≠ .idle) (hv : (s.workers v).phase ≠ .idle)
    (htok : (s.workers w).token = (s.workers v).token) : w = v :=
  Classical.byContradiction fun hne => h.inv.token_unique w v hne hw hv htok

/-- **At most one worker can write.**

Only a worker whose token equals the current attempt number passes the
store's check (`fencing`). There is never more than one such worker. -/
theorem at_most_one_writer {cfg : Config} {s : State} (h : Reachable cfg s) (w v : Nat)
    (hw : (s.workers w).phase ≠ .idle) (hv : (s.workers v).phase ≠ .idle)
    (hwt : (s.workers w).token = s.row.attempts)
    (hvt : (s.workers v).token = s.row.attempts) : w = v :=
  tokens_unique h w v hw hv (hwt.trans hvt.symm)

/-- **The attempt budget is never exceeded.**

Attempts that were not cut short by a shutdown never number more than
`maxAttempts`. Interruptions never outnumber attempts. -/
theorem attempt_budget {cfg : Config} {s : State} (h : Reachable cfg s) :
    s.row.attempts - s.row.interruptions ≤ cfg.maxAttempts ∧
      s.row.interruptions ≤ s.row.attempts := by
  have h1 := h.inv.budget
  have h2 := h.inv.interruptions_le
  exact ⟨by omega, h2⟩

end LeaseProof
