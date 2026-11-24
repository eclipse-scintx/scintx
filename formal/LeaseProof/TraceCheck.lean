/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Reachable

/-!
# The trace judge: tie the Go WORKER code to this model

`Vectors.lean` checks that the Go stores follow the model. This file does
the same for the Go worker code (`worker.go`, `execution.go`,
`heartbeat.go`, `outcome.go`). It works in the other direction.

The model does not say what a worker WILL do. It says what a worker MAY do.
So nothing can be generated here and replayed in Go. Instead, a Go test
runs the real workers and records every call they make to the store
(`internal/gateway/trace_store_test.go`). This file then judges the
recording: is it a run that the model allows?

The judge only ever changes its state with `step`, the function that every
theorem is about. So each state it passes through is `Reachable`, and every
theorem holds for it. Nothing about the worker rules is written down twice.

For one recorded call it checks three things:

1. The model's worker is in a phase in which it makes this call. A worker
   that writes after it has finished is caught here. So is a worker that
   sends an attempt number that is not its own.
2. The worker's own lease deadline is not later than the model's. This is
   the fact that "at most one lease holder" rests on (`LeaseInv`).
3. After the call, the model's row equals the real row. A wrong
   `interruptions` count or a retry delay above the limit is caught here.

How a recorded call maps to model actions is in `Event.actions`. That table
is short, and it is the one part that is checked by reading.
-/

namespace LeaseProof

/-- The store methods a worker calls. `exhaust` is a claim that found the
row out of attempts and marked it `failed`. -/
inductive Call where
  | claim | exhaust | renew | complete | fail | delay | interrupt | release
  deriving DecidableEq

/-- What became of a call on its way to the store. -/
inductive Arrival where
  /-- It arrived, and the store accepted it. -/
  | accepted
  /-- It arrived, and the store refused it. The row did not change. -/
  | refused
  /-- It never arrived (the connection broke first). -/
  | dropped
  deriving DecidableEq

/-- What the worker got back. `error` is any error other than
`ErrStaleAttempt`. The worker can get `error` for a call that arrived: the
connection can break after the write and before the answer. -/
inductive Answer where
  | ok | stale | error
  deriving DecidableEq

/-- One recorded store call. -/
structure Event where
  call : Call
  /-- The attempt number that the worker sent. For a claim: the one it got. -/
  k : Nat
  /-- The clock value that the worker sent. 0 for calls without one. -/
  t : Nat
  /-- The retry delay. 0 for every call but `delay`. -/
  d : Nat
  arrival : Arrival
  answer : Answer
  /-- The worker's own lease deadline at the time of the call, if known.
  The Go heartbeat reveals it as the context deadline of each renewal. -/
  deadline : Option Nat
  /-- The real row after the call. -/
  row : Row

/-- An answer that fits what the store did. Anything else is a broken
recording, for example "the store refused it and the worker got ok". -/
def Event.wellFormed (e : Event) : Bool :=
  match e.arrival, e.answer with
  | .accepted, .ok => true
  | .refused, .stale => true
  | .dropped, .error => true
  -- A lost answer, or a refusal that is not about the attempt number.
  | .accepted, .error => true
  | .refused, .error => true
  | _, _ => false

/-- Which worker of the model makes the call. Attempt numbers are unique
(`tokens_unique`), so the attempt number names the worker. Worker 0 never
owns an attempt, so it stands for "some idle worker". -/
def Event.worker (e : Event) : Nat :=
  if e.call = .exhaust then 0 else e.k

/-- The phase a model worker is in when it makes this call. -/
def Call.phase : Call → Phase
  | .claim | .exhaust => .idle
  | .release => .releasing
  | _ => .executing

/-- The model actions that one recorded call stands for.

A final write that never arrived is `abandon`: the worker stops and the row
is as before. A renewal whose answer got lost is `lateRenew`: the row
changes and the worker does not learn of it. -/
def Event.actions (e : Event) : List Action :=
  let w := e.k
  let dropped := e.arrival = .dropped
  match e.call with
  -- A claim whose answer got lost: the row is claimed, but nobody works.
  | .claim => if e.answer = .error then [.claim w e.t, .abandon w] else [.claim w e.t]
  | .exhaust => [.claim 0 e.t]
  | .renew =>
    if dropped then [] else if e.answer = .error then [.lateRenew w e.t] else [.renew w e.t]
  | .complete => if dropped then [.abandon w] else [.complete w]
  | .fail => if dropped then [.abandon w] else [.fail w]
  | .delay => if dropped then [.abandon w] else [.retry w e.t e.d]
  -- `releaseForShutdown` goes on to release the lease unless it was told
  -- that its attempt is stale. `interruptSkip` is the "goes on" case in
  -- which the row did not change.
  | .interrupt =>
    if e.arrival = .accepted ∨ e.answer = .stale then [.interruptSave w] else [.interruptSkip w]
  | .release => if dropped then [.abandon w] else [.interruptRelease w]

/-- The phase as text, for messages. -/
def Phase.name : Phase → String
  | .idle => "idle"
  | .executing => "executing"
  | .releasing => "releasing"

/-- A row as text, for messages. -/
def Row.text (r : Row) : String :=
  let lease := match r.lease with
    | none => "-"
    | some l => toString l
  s!"{r.status.name} attempts={r.attempts} interruptions={r.interruptions} lease={lease}"

/-- Judge one recorded call. It gives the model's next state, or says which
rule the real worker broke. -/
def judgeEvent (cfg : Config) (s : State) (e : Event) : Except String State := do
  unless e.wellFormed do
    throw "broken recording: the worker's answer does not fit what the store did"
  -- The true time is at least every clock value that was read so far.
  let s := if s.now < e.t then step cfg s (.tick (e.t - s.now)) else s
  let w := s.workers e.worker
  unless w.phase = e.call.phase do
    throw s!"the model never makes this call: its worker {e.worker} is {w.phase.name} here"
  if let some deadline := e.deadline then
    unless deadline ≤ w.deadline do
      throw s!"the worker's lease deadline {deadline} is later than the model's {w.deadline}"
  let s' := run cfg s e.actions
  unless s'.row = e.row do
    throw s!"the rows differ. model: {s'.row.text}. real: {e.row.text}"
  return s'

end LeaseProof
