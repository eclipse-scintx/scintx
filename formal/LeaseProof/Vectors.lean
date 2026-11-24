/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Store

/-!
# Test vectors: tie the Go stores to this model

The proofs are about the model in `Store.lean`. They say nothing about the
Go code unless the Go stores really behave like the model. This file closes
that gap as far as a test can.

It prints a list of scenarios. A scenario is a list of store calls, and
after each call the row that THE MODEL says must result. The Go test
`internal/gateway/lease_vectors_test.go` replays every scenario against the
memory store, SQLite and PostgreSQL, and compares.

The expected rows are computed by the same `Store.*` functions that the
theorems are about. Nobody typed them in by hand.

`scripts/formal.sh` writes the output to
`internal/gateway/testdata/lease_vectors.json`.
-/

namespace LeaseProof

/-- The lease duration every scenario uses. Small, so that leases run out
within a few steps. -/
def vectorLease : Nat := 3

/-- The attempt limit every scenario uses. Small, so that it is reached. -/
def vectorMaxAttempts : Nat := 2

/-- One call to the store. `k` is the attempt number the caller sends, `t`
its clock value, `d` a retry delay, `i` the new `interruptions` count. -/
inductive Op where
  | claim (t : Nat)
  | renew (k t : Nat)
  | delayRetry (k t d : Nat)
  | release (k : Nat)
  | complete (k : Nat)
  | fail (k : Nat)
  | interrupt (k i : Nat)

/-- Turn the answer of a store rule into "the row now, and was it accepted". -/
def answer (r : Row) : Option Row → Row × Bool
  | some r' => (r', true)
  | none => (r, false)

/-- What the model says one call does to the row. -/
def Op.apply (r : Row) : Op → Row × Bool
  | .claim t =>
    match Store.claim vectorMaxAttempts r t vectorLease with
    | .nothing => (r, false)
    -- The row became `failed`, but the caller got nothing to work on.
    | .exhausted r' => (r', false)
    | .claimed r' => (r', true)
  | .renew k t => answer r (Store.renew r k t vectorLease)
  | .delayRetry k t d => answer r (Store.delayRetry r k t d)
  | .release k => answer r (Store.release r k)
  | .complete k => answer r (Store.putCompleted r k)
  | .fail k => answer r (Store.putFailed r k)
  | .interrupt k i => answer r (Store.putRunning r k i)

-- `Status.name` (the status as the Go code spells it) used to be defined
-- here. It moved to `Store.lean`, because `TraceCheck.lean` needs it too.

/-- The JSON fields of a call. A number that the call does not use is 0. -/
def opFields (name : String) (k t d i : Nat) : String :=
  s!"\"op\":\"{name}\",\"k\":{k},\"t\":{t},\"d\":{d},\"i\":{i}"

/-- A call as JSON fields. -/
def Op.json : Op → String
  | .claim t => opFields "claim" 0 t 0 0
  | .renew k t => opFields "renew" k t 0 0
  | .delayRetry k t d => opFields "delayRetry" k t d 0
  | .release k => opFields "release" k 0 0 0
  | .complete k => opFields "complete" k 0 0 0
  | .fail k => opFields "fail" k 0 0 0
  | .interrupt k i => opFields "interrupt" k 0 0 i

/-- One step as JSON: the call, whether it was accepted, and the row after. -/
def stepJson (op : Op) (r : Row) (ok : Bool) : String :=
  let lease := match r.lease with
    | none => "null"
    | some l => toString l
  "{" ++ op.json ++ s!",\"ok\":{ok},\"status\":\"{r.status.name}\"" ++
    s!",\"attempts\":{r.attempts},\"interruptions\":{r.interruptions},\"lease\":{lease}" ++ "}"

/-- One scenario as JSON. It starts from a new submission.

`boundary` is true when some claim arrives at the exact moment a lease
ends. The model then lets the claim through (`lease ≤ now`). PostgreSQL
follows its own real clock, which cannot hit an exact moment, so the Go
test skips these scenarios there. -/
def scenarioJson (ops : List Op) : String :=
  let start : Row × List String × Bool := (Row.fresh, [], false)
  let (_, steps, boundary) := ops.foldl (fun (r, steps, boundary) op =>
    let (r', ok) := op.apply r
    let edge := match op with
      | .claim t => r.lease == some t
      | _ => false
    (r', steps ++ [stepJson op r' ok], boundary || edge)) start
  s!"\{\"boundary\":{boundary},\"steps\":[{",".intercalate steps}]}"

/-- A fixed pseudo-random sequence (a linear congruential generator). It
has no real randomness: the output of this file is the same on every run. -/
def nextSeed (seed : Nat) : Nat := (seed * 1103515245 + 12345) % 2147483648

/-- A number below `n`, taken from the seed. The low bits of this kind of
generator repeat quickly, so the high bits are used. -/
def pick (seed n : Nat) : Nat := (seed / 65536) % n

/-- A scenario of `steps` made-up calls.

The calls are hostile on purpose. The clock value may be stale. The attempt
number is the current one half of the time, and otherwise one too low (a
stale worker) or one too high (a number that was never handed out). -/
def randomOps (seed steps : Nat) : List Op := Id.run do
  let mut seed := seed
  let mut now := 0
  let mut row := Row.fresh
  let mut ops : List Op := []
  for _ in [0:steps] do
    seed := nextSeed seed
    let kind := pick seed 10
    seed := nextSeed seed
    now := now + pick seed 4
    seed := nextSeed seed
    let stale := pick seed 3
    seed := nextSeed seed
    let which := pick seed 4
    let t := now - stale
    let k := match which with
      | 2 => row.attempts - 1
      | 3 => row.attempts + 1
      | _ => row.attempts
    let op := match kind with
      | 0 | 1 | 2 => Op.claim t
      | 3 | 4 => Op.renew k t
      | 5 => Op.delayRetry k t (1 + 2 * stale)
      | 6 => Op.release k
      | 7 => Op.interrupt k (row.interruptions + 1)
      | 8 => Op.complete k
      | _ => Op.fail k
    ops := ops ++ [op]
    row := (op.apply row).1
  return ops

/-- Scenarios written by hand. Each one walks through one rule on purpose. -/
def handPicked : List (List Op) := [
  -- A late renewal must not move the lease back (5 stays 5). The old
  -- attempt is fenced once attempt 2 exists.
  [.claim 0, .renew 1 2, .renew 1 1, .claim 4, .claim 5, .complete 1, .complete 2, .fail 2],
  -- A retry delay may move the lease back (3 becomes 1).
  [.claim 0, .delayRetry 1 0 1, .claim 0, .claim 1, .renew 1 1, .renew 2 1],
  -- The attempt limit: the third claim marks the row failed.
  [.claim 0, .claim 3, .claim 6, .claim 9, .renew 2 9],
  -- Interrupted attempts do not count toward the limit.
  [.claim 0, .interrupt 1 1, .release 1, .claim 0, .interrupt 2 2, .release 2,
    .claim 0, .claim 9, .claim 20, .claim 30],
  -- A row that was never claimed: only "failed" with attempt 0 is accepted.
  [.renew 0 0, .release 0, .complete 0, .delayRetry 0 0 1, .fail 1, .fail 0, .claim 0]]

/-- The whole file: the settings, then one scenario per line. -/
def vectorsJson : String :=
  let random := (List.range 80).map fun n => randomOps (1000 + 7919 * n) 12
  let scenarios := (handPicked ++ random).map scenarioJson
  s!"\{\"leaseDuration\":{vectorLease},\"maxAttempts\":{vectorMaxAttempts},\"scenarios\":[\n" ++
    ",\n".intercalate scenarios ++ "\n]}"

end LeaseProof

/-- Print the test vectors. Run by `scripts/formal.sh`. -/
def main : IO Unit := IO.println LeaseProof.vectorsJson
