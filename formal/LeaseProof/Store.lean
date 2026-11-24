/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/

/-!
# The store: one submission row and the rules for changing it

This file is a model of the Go `Store` interface in
`internal/gateway/store.go`. Each function below mirrors one Go method, for
both `MemoryStore` and `SQLStore`.

The model keeps only the columns that the lease logic reads or writes:

| Model field     | Go / SQL                                        |
|-----------------|-------------------------------------------------|
| `status`        | `status` column, `api.SubmissionStatus`         |
| `attempts`      | `attempts` column. It is also the fencing token |
| `interruptions` | `Submission.Interruptions` inside `payload_json`|
| `lease`         | `lease_until` column. `none` is the empty string|

Time is a natural number. Only the order of two times matters, never the
unit, so this loses nothing.

The model has ONE row. This is enough because every store operation reads
and writes a single row. Which row a claim picks (the queue order) changes
who goes first. It does not change what may happen to a row.
-/

namespace LeaseProof

/-- The submission status. Mirrors `api.SubmissionStatus`. -/
inductive Status where
  | accepted
  | running
  | completed
  | failed
  deriving DecidableEq, Repr

/-- `completed` and `failed` are the terminal states (`IsTerminal` in Go). -/
def Status.isTerminal : Status → Bool
  | .completed => true
  | .failed => true
  | _ => false

/-- The status as the Go code spells it. The test vectors (`Vectors.lean`)
and the trace judge (`TraceCheck.lean`) use it to talk to the Go tests. -/
def Status.name : Status → String
  | .accepted => "accepted"
  | .running => "running"
  | .completed => "completed"
  | .failed => "failed"

/-- One row of the `submissions` table. -/
structure Row where
  status : Status
  /-- How many times the row was claimed. Also the fencing token. -/
  attempts : Nat
  /-- How many attempts a graceful shutdown cut short. -/
  interruptions : Nat
  /-- When the lease runs out. `none` means "no lease". -/
  lease : Option Nat
  deriving DecidableEq, Repr

/-- A new submission, as written by `Orchestrator.Submit`. -/
def Row.fresh : Row :=
  { status := .accepted, attempts := 0, interruptions := 0, lease := none }

/-- A lease is expired when there is none, or when it ended at or before
`now`. Mirrors `lease_until = '' OR lease_until <= ?` in `sql_claim.go`. -/
def leaseExpired (lease : Option Nat) (now : Nat) : Bool :=
  match lease with
  | none => true
  | some l => decide (l ≤ now)

/-- What `ClaimNextSubmission` did. -/
inductive ClaimOutcome where
  /-- The row could not be claimed. Nothing changed. -/
  | nothing
  /-- The row was out of attempts, so the store marked it `failed`. -/
  | exhausted (r : Row)
  /-- The caller now owns attempt number `r.attempts`. -/
  | claimed (r : Row)

/-- Mirrors `ClaimNextSubmission`.

A row can be claimed when it is not finished and its lease is expired. If
its attempt budget is used up, it is marked `failed` instead. The budget
check is `Submission.AttemptsExhausted`: attempts that a shutdown cut short
do not count. -/
def Store.claim (maxAttempts : Nat) (r : Row) (now leaseDuration : Nat) : ClaimOutcome :=
  if (r.status = .accepted ∨ r.status = .running) ∧ leaseExpired r.lease now = true then
    if maxAttempts ≤ r.attempts - r.interruptions then
      .exhausted { r with status := .failed, lease := none }
    else
      .claimed { r with
        status := .running,
        attempts := r.attempts + 1,
        lease := some (now + leaseDuration) }
  else
    .nothing

/-- The later of the stored lease and a new one. With no stored lease it is
the new one. Mirrors `MAX(lease_until, ?)` in `sql_lease.go`. -/
def extendLease (lease : Option Nat) (new : Nat) : Nat :=
  match lease with
  | none => new
  | some l => max l new

/-- Mirrors `RenewLease`. `none` stands for `ErrStaleAttempt`.

The write is refused unless the caller's attempt number is the current one
and the row is still running. This guard is the fencing check.

A renewal only moves the lease FORWARD (`extendLease`). An earlier version
of this model, like the Go code then, set the lease to `now + duration` in
every case. The proofs showed the flaw: an old renewal that landed after a
newer one moved the lease back, and two workers could hold it at once. -/
def Store.renew (r : Row) (attempt now duration : Nat) : Option Row :=
  if r.status = .running ∧ r.attempts = attempt then
    some { r with lease := some (extendLease r.lease (now + duration)) }
  else
    none

/-- Mirrors `DelayRetry`. `none` stands for `ErrStaleAttempt`.

It SETS the lease to `now + delay`, so it may move the lease back. A retry
delay is often shorter than what is left of the lease. -/
def Store.delayRetry (r : Row) (attempt now delay : Nat) : Option Row :=
  if r.status = .running ∧ r.attempts = attempt then
    some { r with lease := some (now + delay) }
  else
    none

/-- Mirrors `ReleaseLease`. `none` stands for `ErrStaleAttempt`. -/
def Store.release (r : Row) (attempt : Nat) : Option Row :=
  if r.status = .running ∧ r.attempts = attempt then
    some { r with lease := none }
  else
    none

/-- Mirrors `PutSubmission` with status `completed`. `none` means refused.
Only allowed from `running`. It clears the lease. -/
def Store.putCompleted (r : Row) (attempt : Nat) : Option Row :=
  if r.status = .running ∧ r.attempts = attempt then
    some { r with status := .completed, lease := none }
  else
    none

/-- Mirrors `PutSubmission` with status `failed`. `none` means refused.
Allowed from `accepted` or `running`. It clears the lease. -/
def Store.putFailed (r : Row) (attempt : Nat) : Option Row :=
  if (r.status = .accepted ∨ r.status = .running) ∧ r.attempts = attempt then
    some { r with status := .failed, lease := none }
  else
    none

/-- Mirrors `PutSubmission` with status `running`. `none` means refused.

The only caller is `releaseForShutdown`, which uses it to save a new
`interruptions` count. The lease is kept as it is. -/
def Store.putRunning (r : Row) (attempt interruptions : Nat) : Option Row :=
  if (r.status = .accepted ∨ r.status = .running) ∧ r.attempts = attempt then
    some { r with status := .running, interruptions := interruptions }
  else
    none

-- The facts that the proofs use about these operations are in
-- `StoreLemmas.lean`. They were moved there to keep this file small.

end LeaseProof
