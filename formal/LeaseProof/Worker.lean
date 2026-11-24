/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Store

/-!
# Workers, settings, and the state of the whole system

These are the data types of the model. What can happen to them is in
`Model.lean`. They were split out of `Model.lean` to keep each file small.
-/

namespace LeaseProof

/-- Where a worker is in one attempt. -/
inductive Phase where
  /-- Not working on the submission. -/
  | idle
  /-- Running the attempt (the execution hook). -/
  | executing
  /-- A shutdown interrupted it. It saved the interruption and still has to
  release the lease. These are two writes in `releaseForShutdown`. -/
  | releasing
  deriving DecidableEq, Repr

/-- What one worker remembers about its attempt. -/
structure Worker where
  phase : Phase
  /-- The attempt number it got from the claim. Its fencing token. -/
  token : Nat
  /-- When the worker thinks its lease runs out (`leaseDeadline` in Go). -/
  deadline : Nat
  /-- The `interruptions` count in its copy of the submission. -/
  seen : Nat
  deriving DecidableEq, Repr

/-- A worker that is doing nothing. -/
def Worker.idle : Worker := { phase := .idle, token := 0, deadline := 0, seen := 0 }

/-- Settings of the model. -/
structure Config where
  /-- `leaseDuration` in Go. -/
  leaseDuration : Nat
  /-- `maxAttempts` in Go. -/
  maxAttempts : Nat
  /-- The longest retry backoff. In Go, `retryDelay` doubles at most
  `maxBackoffDoublings` times, so it has such a limit. -/
  maxRetryDelay : Nat
  /-- How far AHEAD of the true time a gateway's clock may run. Zero means
  that no gateway's clock is fast. Only the lease theorems need zero.

  "The true time" is the clock that the leases in the store are compared
  with. On PostgreSQL that is the database's own clock, and the store never
  takes a date from a gateway, so this is zero by construction there. -/
  clockAhead : Nat

/-- The whole system at one moment. -/
structure State where
  /-- The true time. -/
  now : Nat
  row : Row
  workers : Nat → Worker

/-- Replace worker `w` and leave all others as they are. -/
def setWorker (ws : Nat → Worker) (w : Nat) (x : Worker) : Nat → Worker :=
  fun v => if v = w then x else ws v

end LeaseProof
