/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Reachable

/-!
# The invariant: facts that are true in every reachable state

An invariant is proven in two parts: it holds at the start, and every action
keeps it. It then holds after any number of actions, in any order.

Nothing in this file talks about time. So everything here holds even when
the clocks of the gateways disagree by any amount. The facts that DO depend
on clocks are in `Lease.lean`.
-/

namespace LeaseProof

/-- The facts that every action keeps true. -/
structure Inv (cfg : Config) (s : State) : Prop where
  /-- There are never more interruptions than attempts. -/
  interruptions_le : s.row.interruptions ≤ s.row.attempts
  /-- The attempt budget: attempts that were not interrupted never exceed
  `maxAttempts`. -/
  budget : s.row.attempts ≤ s.row.interruptions + cfg.maxAttempts
  /-- An `accepted` row was never claimed and has no lease. -/
  accepted_fresh : s.row.status = .accepted → s.row.attempts = 0 ∧ s.row.lease = none
  /-- A finished row has no lease. -/
  terminal_no_lease : s.row.status.isTerminal = true → s.row.lease = none
  /-- A busy worker's token is a real attempt number, not a future one. Its
  copy of `interruptions` is from before its own attempt. -/
  token_range : ∀ w, (s.workers w).phase ≠ .idle →
    1 ≤ (s.workers w).token ∧ (s.workers w).token ≤ s.row.attempts ∧
      (s.workers w).seen < (s.workers w).token
  /-- No two busy workers have the same token. -/
  token_unique : ∀ w v, w ≠ v → (s.workers w).phase ≠ .idle → (s.workers v).phase ≠ .idle →
    (s.workers w).token ≠ (s.workers v).token
  /-- The worker that owns the newest attempt has an up-to-date copy of
  `interruptions`. So its "plus one" on shutdown is correct. -/
  owner_seen : ∀ w, (s.workers w).phase = .executing →
    (s.workers w).token = s.row.attempts → (s.workers w).seen = s.row.interruptions

/-- The invariant holds at the start. -/
theorem Inv.init (cfg : Config) : Inv cfg State.init := by
  constructor <;> simp [State.init, Row.fresh, Worker.idle, Status.isTerminal]

/-- A general rule that covers most actions.

The invariant survives any change that (1) keeps `attempts` and
`interruptions`, (2) keeps the two row facts true, and (3) gives no worker a
new token: each busy worker was busy before, with the same token. -/
theorem Inv.frame {cfg : Config} {s : State} (h : Inv cfg s) (s' : State)
    (hatt : s'.row.attempts = s.row.attempts)
    (hint : s'.row.interruptions = s.row.interruptions)
    (hacc : s'.row.status = .accepted → s'.row.attempts = 0 ∧ s'.row.lease = none)
    (hterm : s'.row.status.isTerminal = true → s'.row.lease = none)
    (hws : ∀ v, (s'.workers v).phase ≠ .idle →
      (s.workers v).phase ≠ .idle ∧ (s'.workers v).token = (s.workers v).token ∧
        (s'.workers v).seen = (s.workers v).seen ∧
        ((s'.workers v).phase = .executing → (s.workers v).phase = .executing)) :
    Inv cfg s' := by
  constructor
  · rw [hatt, hint]; exact h.interruptions_le
  · rw [hatt, hint]; exact h.budget
  · exact hacc
  · exact hterm
  · intro v hv
    obtain ⟨h1, h2, h3, _⟩ := hws v hv
    rw [h2, h3, hatt]; exact h.token_range v h1
  · intro w v hne hw hv
    obtain ⟨hw1, hw2, _, _⟩ := hws w hw
    obtain ⟨hv1, hv2, _, _⟩ := hws v hv
    rw [hw2, hv2]; exact h.token_unique w v hne hw1 hv1
  · intro w hw htok
    have hbusy : (s'.workers w).phase ≠ .idle := by rw [hw]; decide
    obtain ⟨_, h2, h3, h4⟩ := hws w hbusy
    rw [h3, hint]
    exact h.owner_seen w (h4 hw) (by rw [← h2, htok, hatt])

/-- Making one worker idle never gives anyone a new token. -/
theorem idle_keeps_tokens (s : State) (w : Nat) :
    ∀ v, (setWorker s.workers w Worker.idle v).phase ≠ .idle →
      (s.workers v).phase ≠ .idle ∧
        (setWorker s.workers w Worker.idle v).token = (s.workers v).token ∧
        (setWorker s.workers w Worker.idle v).seen = (s.workers v).seen ∧
        ((setWorker s.workers w Worker.idle v).phase = .executing →
          (s.workers v).phase = .executing) := by
  intro v hv
  unfold setWorker at hv ⊢
  split at hv
  · exact absurd rfl hv
  · next hne => simp [hne]; exact hv

/-- Changing only what worker `w` remembers, with the same token and the
same `seen`, never gives anyone a new token. The new phase must not turn a
worker that was not executing into one that is. -/
theorem update_keeps_tokens (s : State) (w : Nat) (x : Worker)
    (hbusy : (s.workers w).phase ≠ .idle)
    (htok : x.token = (s.workers w).token) (hseen : x.seen = (s.workers w).seen)
    (hexec : x.phase = .executing → (s.workers w).phase = .executing) :
    ∀ v, (setWorker s.workers w x v).phase ≠ .idle →
      (s.workers v).phase ≠ .idle ∧
        (setWorker s.workers w x v).token = (s.workers v).token ∧
        (setWorker s.workers w x v).seen = (s.workers v).seen ∧
        ((setWorker s.workers w x v).phase = .executing →
          (s.workers v).phase = .executing) := by
  intro v hv
  unfold setWorker at hv ⊢
  split
  · next heq => subst heq; exact ⟨hbusy, htok, hseen, hexec⟩
  · next hne => simp [hne] at hv; exact ⟨hv, rfl, rfl, id⟩

end LeaseProof
