/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Model

/-!
# Every state the system can reach

The theorems are statements about "every reachable state". This file says
what that means. It was split out of `Model.lean` to keep each file small.
-/

namespace LeaseProof

/-- The start: time zero, a new submission, and every worker idle. -/
def State.init : State :=
  { now := 0, row := Row.fresh, workers := fun _ => Worker.idle }

/-- The states the system can ever be in: the start, and anything that one
more action leads to. A theorem about every `Reachable` state is a theorem
about every possible run, of any length, with any number of workers. -/
inductive Reachable (cfg : Config) : State → Prop where
  | init : Reachable cfg State.init
  | step {s : State} (a : Action) : Reachable cfg s → Reachable cfg (step cfg s a)

/-- Run a list of actions in order. Used to build example runs. -/
def run (cfg : Config) (s : State) (actions : List Action) : State :=
  actions.foldl (step cfg) s

/-- Any state reached by running actions from a reachable state is reachable. -/
theorem Reachable.run {cfg : Config} {s : State} (h : Reachable cfg s) (actions : List Action) :
    Reachable cfg (run cfg s actions) := by
  induction actions generalizing s with
  | nil => exact h
  | cons a rest ih => exact ih (Reachable.step a h)

/-- A worker holds the lease when it is running an attempt and its own
deadline has not passed yet. -/
def holdsLease (s : State) (w : Nat) : Prop :=
  (s.workers w).phase = .executing ∧ s.now < (s.workers w).deadline

end LeaseProof
