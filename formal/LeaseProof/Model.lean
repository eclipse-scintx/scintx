/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Worker

/-!
# The workers: who calls the store, and when

This file is a model of the Go worker logic in `internal/gateway`:
`worker.go`, `execution.go`, `heartbeat.go` and `outcome.go`.

A state is the current time, the one row, and any number of workers (see
`Worker.lean`). Workers are numbered 0, 1, 2, ... without limit, so the
proofs cover any pool size and any number of gateway instances.

Every event is an `Action`. `step` says how one action changes the state.
The proofs then show that no order of actions can break the rules.

## What the model deliberately allows

The model is more hostile than the real code, so the proofs cover more:

* **Stale timestamps.** Go reads the clock and then calls the database. The
  write lands later. So an action carries the time `t` that was read, and
  `t` may be older than the true time by any amount.
* **Crashes anywhere.** `abandon` makes a worker vanish at any moment, with
  no write. It also stands for a lost lease, a failed final write, and a
  process kill.
* **Final writes without a valid lease.** A worker may try to save a result
  long after its lease ran out, exactly as the Go code does.
* **Lost answers and late writes.** A write can land while its sender only
  sees an error. It can even land after the sender gave up on it and moved
  on. For final writes the sender stops either way, so the normal action
  covers it. For a heartbeat renewal it is the extra action `lateRenew`.
-/

namespace LeaseProof

/-- Everything that can happen. `w` is the worker that acts. `t` is the
clock value it read before it called the store. -/
inductive Action where
  /-- Time passes. -/
  | tick (d : Nat)
  /-- `claimAndExecuteOne`: an idle worker tries to claim the row. -/
  | claim (w t : Nat)
  /-- The heartbeat calls `RenewLease`. -/
  | renew (w t : Nat)
  /-- `completeSubmission`: save "completed". -/
  | complete (w : Nat)
  /-- `failSubmission`: save "failed". -/
  | fail (w : Nat)
  /-- `scheduleRetry`: push the lease `delay` into the future. -/
  | retry (w t delay : Nat)
  /-- `releaseForShutdown`, first write: save `interruptions + 1`. -/
  | interruptSave (w : Nat)
  /-- `releaseForShutdown` when the first write failed for a reason other
  than a stale attempt. The code then still goes on to release the lease. -/
  | interruptSkip (w : Nat)
  /-- `releaseForShutdown`, second write: `ReleaseLease`. -/
  | interruptRelease (w : Nat)
  /-- The worker stops without writing anything (crash, lost lease, ...). -/
  | abandon (w : Nat)
  /-- A heartbeat renewal for attempt `k` that lands without its sender
  learning of it. Either the answer was lost (the connection dropped right
  after the commit), or the renewal was stuck and lands LATE, after its
  sender gave up on it and moved on. No worker changes. The clock value
  `t` may be as old as you like.

  An earlier version of the model had a switch to forbid this action,
  because it broke the lease. Renewals are forward-only now, so the action
  is always allowed and the lease theorems hold anyway. -/
  | lateRenew (k t : Nat)

/-- One action. An action that is not allowed right now changes nothing. -/
def step (cfg : Config) (s : State) : Action → State
  | .tick d => { s with now := s.now + d }
  | .claim w t =>
    if (s.workers w).phase = .idle ∧ t ≤ s.now + cfg.clockAhead then
      match Store.claim cfg.maxAttempts s.row t cfg.leaseDuration with
      | .nothing => s
      | .exhausted r => { s with row := r }
      | .claimed r =>
        { s with
          row := r,
          workers := setWorker s.workers w
            { phase := .executing, token := r.attempts,
              deadline := t + cfg.leaseDuration, seen := r.interruptions } }
    else s
  | .renew w t =>
    if (s.workers w).phase = .executing ∧ t ≤ s.now + cfg.clockAhead then
      match Store.renew s.row (s.workers w).token t cfg.leaseDuration with
      | some r =>
        { s with
          row := r,
          workers := setWorker s.workers w
            { s.workers w with deadline := t + cfg.leaseDuration } }
      -- ErrStaleAttempt: the heartbeat cancels the attempt.
      | none => { s with workers := setWorker s.workers w Worker.idle }
    else s
  | .complete w =>
    if (s.workers w).phase = .executing then
      match Store.putCompleted s.row (s.workers w).token with
      | some r => { s with row := r, workers := setWorker s.workers w Worker.idle }
      | none => { s with workers := setWorker s.workers w Worker.idle }
    else s
  | .fail w =>
    if (s.workers w).phase = .executing then
      match Store.putFailed s.row (s.workers w).token with
      | some r => { s with row := r, workers := setWorker s.workers w Worker.idle }
      | none => { s with workers := setWorker s.workers w Worker.idle }
    else s
  | .retry w t delay =>
    if (s.workers w).phase = .executing ∧ t ≤ s.now + cfg.clockAhead ∧
        delay ≤ cfg.maxRetryDelay then
      match Store.delayRetry s.row (s.workers w).token t delay with
      | some r => { s with row := r, workers := setWorker s.workers w Worker.idle }
      | none => { s with workers := setWorker s.workers w Worker.idle }
    else s
  | .interruptSave w =>
    if (s.workers w).phase = .executing then
      match Store.putRunning s.row (s.workers w).token ((s.workers w).seen + 1) with
      | some r =>
        { s with
          row := r,
          workers := setWorker s.workers w { s.workers w with phase := .releasing } }
      -- ErrStaleAttempt: a newer attempt owns the row. Leave it alone.
      | none => { s with workers := setWorker s.workers w Worker.idle }
    else s
  | .interruptSkip w =>
    if (s.workers w).phase = .executing then
      { s with workers := setWorker s.workers w { s.workers w with phase := .releasing } }
    else s
  | .interruptRelease w =>
    if (s.workers w).phase = .releasing then
      match Store.release s.row (s.workers w).token with
      | some r => { s with row := r, workers := setWorker s.workers w Worker.idle }
      | none => { s with workers := setWorker s.workers w Worker.idle }
    else s
  | .abandon w => { s with workers := setWorker s.workers w Worker.idle }
  | .lateRenew k t =>
    if t ≤ s.now + cfg.clockAhead then
      match Store.renew s.row k t cfg.leaseDuration with
      | some r => { s with row := r }
      | none => s
    else s

end LeaseProof
