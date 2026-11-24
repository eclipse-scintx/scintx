/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Invariant
import LeaseProof.StoreLemmas

/-!
# The three kinds of change that need their own proof

Most actions are covered by the general rule `Inv.frame`. These need more:

* a successful claim, which creates a new token,
* saving an interruption, which changes the `interruptions` count, and
* a change of the lease only (a small shortcut for `Inv.frame`).

They were split out of `Step.lean` to keep each file small.
-/

namespace LeaseProof

/-- A successful claim keeps the invariant.

The new token is `attempts + 1`. Every token handed out before is at most
`attempts`. So the new token is different from all of them. -/
theorem Inv.claimed {cfg : Config} {s : State} (h : Inv cfg s) (w t : Nat)
    (hbud : s.row.attempts - s.row.interruptions < cfg.maxAttempts) :
    Inv cfg { s with
      row := { s.row with
        status := .running, attempts := s.row.attempts + 1,
        lease := some (t + cfg.leaseDuration) },
      workers := setWorker s.workers w
        { phase := .executing, token := s.row.attempts + 1,
          deadline := t + cfg.leaseDuration, seen := s.row.interruptions } } := by
  have hi := h.interruptions_le
  have hrange := h.token_range
  constructor
  · show s.row.interruptions ≤ s.row.attempts + 1
    omega
  · show s.row.attempts + 1 ≤ s.row.interruptions + cfg.maxAttempts
    omega
  · intro hc; cases hc
  · intro hc; cases hc
  · intro v hv
    simp only [setWorker] at hv ⊢
    split at hv
    · next heq => simp only [heq, ↓reduceIte]; omega
    · next hne => simp only [hne, ↓reduceIte]; have := hrange v hv; omega
  · intro u v hne hu hv
    simp only [setWorker] at hu hv ⊢
    split at hu <;> split at hv
    · next h1 h2 => exact absurd (h1.trans h2.symm) hne
    · next h1 h2 => simp only [h1, h2, ↓reduceIte]; have := hrange v hv; omega
    · next h1 h2 => simp only [h1, h2, ↓reduceIte]; have := hrange u hu; omega
    · next h1 h2 => simp only [h1, h2, ↓reduceIte]; exact h.token_unique u v hne hu hv
  · intro v hv htok
    simp only [setWorker] at hv htok ⊢
    split at hv
    · next heq => simp only [heq, ↓reduceIte]
    · next hne =>
      simp only [hne, ↓reduceIte] at htok
      have hbusy : (s.workers v).phase ≠ .idle := by rw [hv]; decide
      have := hrange v hbusy
      omega

/-- Saving an interruption keeps the invariant.

Only the worker that owns the newest attempt can do it (the store checks the
token). Its copy of `interruptions` is up to date, so "plus one" is right. -/
theorem Inv.interrupted {cfg : Config} {s : State} (h : Inv cfg s) (w : Nat)
    (hexec : (s.workers w).phase = .executing)
    (hown : s.row.attempts = (s.workers w).token) :
    Inv cfg { s with
      row := { s.row with status := .running, interruptions := (s.workers w).seen + 1 },
      workers := setWorker s.workers w { s.workers w with phase := .releasing } } := by
  have hbusy : (s.workers w).phase ≠ .idle := by rw [hexec]; decide
  have hrange := h.token_range w hbusy
  have hseen := h.owner_seen w hexec hown.symm
  have hbud := h.budget
  constructor
  · show (s.workers w).seen + 1 ≤ s.row.attempts
    omega
  · show s.row.attempts ≤ (s.workers w).seen + 1 + cfg.maxAttempts
    omega
  · intro hc; cases hc
  · intro hc; cases hc
  · intro v hv
    simp only [setWorker] at hv ⊢
    split
    · next heq => subst heq; exact hrange
    · next hne => simp only [hne, ↓reduceIte] at hv; exact h.token_range v hv
  · intro u v hne hu hv
    simp only [setWorker] at hu hv ⊢
    split at hu <;> split at hv
    · next h1 h2 => exact absurd (h1.trans h2.symm) hne
    · next h1 h2 => subst h1; simp only [h2, ↓reduceIte]; exact h.token_unique u v hne hbusy hv
    · next h1 h2 => subst h2; simp only [h1, ↓reduceIte]; exact h.token_unique u v hne hu hbusy
    · next h1 h2 => simp only [h1, h2, ↓reduceIte]; exact h.token_unique u v hne hu hv
  · intro v hv htok
    simp only [setWorker] at hv htok ⊢
    split at hv
    · cases hv
    · next hne =>
      simp only [hne, ↓reduceIte] at htok
      have hvbusy : (s.workers v).phase ≠ .idle := by rw [hv]; decide
      exact absurd (htok.trans hown) (h.token_unique v w hne hvbusy hbusy)

/-- Changing only the lease of a running row keeps the invariant. No worker
changes. This covers a renewal that its sender does not learn about. -/
theorem Inv.lease_changed {cfg : Config} {s : State} (h : Inv cfg s) (l : Option Nat)
    (hrun : s.row.status = .running) :
    Inv cfg { s with row := { s.row with lease := l } } :=
  h.frame _ rfl rfl (fun hc => by simp [hrun] at hc)
    (fun hc => by simp [hrun, Status.isTerminal] at hc) (fun v hv => ⟨hv, rfl, rfl, id⟩)

end LeaseProof
