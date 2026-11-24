/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Step

/-!
# Lease theorems: these need clocks that agree

A lease is a promise about time: "nobody else will claim this row before
time T". The store has no clock of its own. Each gateway passes in its own
clock value. So the promise is only as good as the clocks.

The lease theorems (`LeaseSafety.lean`) therefore need one assumption:
`cfg.clockAhead = 0`. No gateway's clock runs ahead of the true time. Stale
clock readings (read the clock, then reach the database later) are still
allowed. `Limits.lean` proves that the assumption is really needed.

An earlier version needed a second assumption: no renewal lands late. That
one is gone. Renewals are forward-only now, so a late one does no harm.
-/

namespace LeaseProof

/-- The lease fact that every action keeps true.

A worker that is running an attempt is in one of two situations:

1. It owns the newest attempt, the row is running, and the lease in the
   database lasts at least as long as the worker believes.
2. Its own deadline has already passed.

The Go code keeps this true by always computing the local deadline from the
clock value it sent to the store (see `heartbeat.go`). -/
def LeaseInv (s : State) : Prop :=
  ∀ w, (s.workers w).phase = .executing →
    ((s.workers w).token = s.row.attempts ∧ s.row.status = .running ∧
      ∃ l, s.row.lease = some l ∧ (s.workers w).deadline ≤ l) ∨
    (s.workers w).deadline ≤ s.now

theorem LeaseInv.init : LeaseInv State.init := by
  intro w hw
  cases hw

/-- The row is untouched and time does not go back. No worker starts
executing, and no executing worker changes its token or deadline. -/
theorem LeaseInv.frame {s : State} (h : LeaseInv s) (s' : State)
    (hrow : s'.row = s.row) (hnow : s.now ≤ s'.now)
    (hws : ∀ v, (s'.workers v).phase = .executing →
      (s.workers v).phase = .executing ∧ (s'.workers v).token = (s.workers v).token ∧
        (s'.workers v).deadline = (s.workers v).deadline) :
    LeaseInv s' := by
  intro v hv
  obtain ⟨h1, h2, h3⟩ := hws v hv
  rw [h2, h3, hrow]
  rcases h v h1 with hl | hd
  · exact Or.inl hl
  · exact Or.inr (Nat.le_trans hd hnow)

/-- The owner of the newest attempt stops executing, and the row changes in
any way. Every other executing worker has an older token (tokens are
unique), so its deadline had already passed. -/
theorem LeaseInv.owner_done {cfg : Config} {s : State} (hi : Inv cfg s) (h : LeaseInv s)
    (w : Nat) (r : Row) (x : Worker)
    (hbusy : (s.workers w).phase ≠ .idle) (hown : s.row.attempts = (s.workers w).token)
    (hx : x.phase ≠ .executing) :
    LeaseInv { s with row := r, workers := setWorker s.workers w x } := by
  intro v hv
  simp only [setWorker] at hv ⊢
  split at hv
  · exact absurd hv hx
  · next hne =>
    simp only [hne, ↓reduceIte]
    have hvbusy : (s.workers v).phase ≠ .idle := by rw [hv]; decide
    rcases h v hv with ⟨htok, _⟩ | hd
    · exact absurd (htok.trans hown) (hi.token_unique v w hne hvbusy hbusy)
    · exact Or.inr hd

/-- A worker goes idle and the row is untouched. -/
theorem LeaseInv.drop {s : State} (h : LeaseInv s) (w : Nat) :
    LeaseInv { s with workers := setWorker s.workers w Worker.idle } := by
  refine h.frame _ ?_ ?_ ?_
  · rfl
  · exact Nat.le_refl _
  · intro v hv
    simp only [setWorker] at hv ⊢
    split at hv
    · cases hv
    · next hne => simp [hne, hv]

/-- A successful renewal. The worker sets its deadline to exactly the value
it sent to the store, so it never believes longer than the database does. -/
theorem LeaseInv.renewed {cfg : Config} {s : State} (hi : Inv cfg s) (h : LeaseInv s)
    (w t d : Nat) (hexec : (s.workers w).phase = .executing)
    (hown : s.row.attempts = (s.workers w).token) (hrun : s.row.status = .running) :
    LeaseInv { s with
      row := { s.row with lease := some (extendLease s.row.lease (t + d)) },
      workers := setWorker s.workers w { s.workers w with deadline := t + d } } := by
  have hbusy : (s.workers w).phase ≠ .idle := by rw [hexec]; decide
  intro v hv
  simp only [setWorker] at hv ⊢
  split at hv
  · next heq =>
    simp only [heq, ↓reduceIte]
    -- The stored lease is the later of the old lease and `t + d`. So it is
    -- at least `t + d`, which is the worker's new deadline.
    exact Or.inl ⟨hown.symm, hrun, _, rfl, le_extendLease_new⟩
  · next hne =>
    simp only [hne, ↓reduceIte]
    have hvbusy : (s.workers v).phase ≠ .idle := by rw [hv]; decide
    rcases h v hv with ⟨htok, _⟩ | hd
    · exact absurd (htok.trans hown) (hi.token_unique v w hne hvbusy hbusy)
    · exact Or.inr hd

/-- A renewal that no worker learns about (a lost answer or a late write).

Every worker keeps its deadline. A renewal only moves the lease forward, so
the stored lease is still at least as late as any deadline it covered.

This is where "renewals are forward-only" is needed. With a renewal that
SETS the lease, an old one could move the lease to before a deadline. -/
theorem LeaseInv.lease_extended {s : State} (h : LeaseInv s) (new : Nat) :
    LeaseInv { s with row := { s.row with lease := some (extendLease s.row.lease new) } } := by
  intro v hv
  rcases h v hv with ⟨htok, hrun, l, hl, hdl⟩ | hd
  · exact Or.inl ⟨htok, hrun, _, rfl, Nat.le_trans hdl (le_extendLease_old hl)⟩
  · exact Or.inr hd

/-- When the store lets a claim through at time `t ≤ now`, every worker
that was executing has a deadline that already passed.

This is the heart of the lease: the store only allows a claim after the old
lease ended, and no worker believes longer than the store's lease. -/
theorem LeaseInv.expired_at_claim {s : State} (h : LeaseInv s) (t : Nat) (ht : t ≤ s.now)
    (hexp : leaseExpired s.row.lease t = true) (v : Nat)
    (hv : (s.workers v).phase = .executing) : (s.workers v).deadline ≤ s.now := by
  rcases h v hv with ⟨_, _, l, hl, hdl⟩ | hd
  · rw [hl] at hexp
    have := leaseExpired_some.mp hexp
    omega
  · exact hd

/-- A successful claim. -/
theorem LeaseInv.claimed {s : State} (h : LeaseInv s) (w t d : Nat) (ht : t ≤ s.now)
    (hexp : leaseExpired s.row.lease t = true) :
    LeaseInv { s with
      row := { s.row with
        status := .running, attempts := s.row.attempts + 1, lease := some (t + d) },
      workers := setWorker s.workers w
        { phase := .executing, token := s.row.attempts + 1,
          deadline := t + d, seen := s.row.interruptions } } := by
  intro v hv
  simp only [setWorker] at hv ⊢
  split at hv
  · next heq =>
    -- The claiming worker: its token is the new attempt number, and its
    -- deadline is exactly the lease that the store just wrote.
    simp [heq]
  · next hne =>
    simp only [hne, ↓reduceIte]
    exact Or.inr (h.expired_at_claim t ht hexp v hv)

/-- A claim that found the row out of attempts and marked it `failed`. -/
theorem LeaseInv.exhausted {s : State} (h : LeaseInv s) (t : Nat) (ht : t ≤ s.now)
    (hexp : leaseExpired s.row.lease t = true) :
    LeaseInv { s with row := { s.row with status := .failed, lease := none } } := by
  intro v hv
  exact Or.inr (h.expired_at_claim t ht hexp v hv)

end LeaseProof
