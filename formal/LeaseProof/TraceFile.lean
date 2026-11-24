/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.TraceCheck

/-!
# Reading a trace file and judging every run in it

The Go test writes one text file. It holds one run per submission:

    run <label> <leaseDuration> <maxAttempts> <maxRetryDelay>
    ev <call> <k> <t> <d> <arrival> <answer> <deadline> <status> <attempts> <interruptions> <lease>
    ev ...

All times are whole numbers (nanoseconds in the Go test). `-` stands for
"no deadline" and "no lease". The fields of an `ev` line are the fields of
`Event` in `TraceCheck.lean`, in the same order.

Each run starts from a new submission (`State.init`) and is judged line by
line with `judgeEvent`. `JudgeTraces.lean` (one folder up) is the program
that the Go test calls.
-/

namespace LeaseProof

def parseCall : String → Option Call
  | "claim" => some .claim
  | "exhaust" => some .exhaust
  | "renew" => some .renew
  | "complete" => some .complete
  | "fail" => some .fail
  | "delay" => some .delay
  | "interrupt" => some .interrupt
  | "release" => some .release
  | _ => none

def parseArrival : String → Option Arrival
  | "accepted" => some .accepted
  | "refused" => some .refused
  | "dropped" => some .dropped
  | _ => none

def parseAnswer : String → Option Answer
  | "ok" => some .ok
  | "stale" => some .stale
  | "error" => some .error
  | _ => none

def parseStatus : String → Option Status
  | "accepted" => some .accepted
  | "running" => some .running
  | "completed" => some .completed
  | "failed" => some .failed
  | _ => none

/-- A number, or `-` for "none". -/
def parseOptional (s : String) : Option (Option Nat) :=
  if s = "-" then some none else s.toNat?.map some

/-- The fields of an `ev` line, after the word `ev`. -/
def parseEvent : List String → Option Event
  | [call, k, t, d, arrival, answer, deadline, status, attempts, interruptions, lease] => do
    let row : Row :=
      { status := ← parseStatus status, attempts := ← attempts.toNat?,
        interruptions := ← interruptions.toNat?, lease := ← parseOptional lease }
    return { call := ← parseCall call, k := ← k.toNat?, t := ← t.toNat?, d := ← d.toNat?,
             arrival := ← parseArrival arrival, answer := ← parseAnswer answer,
             deadline := ← parseOptional deadline, row }
  | _ => none

/-- Where the judge stands while it reads the file. -/
structure Verdict where
  cfg : Config := { leaseDuration := 0, maxAttempts := 0, maxRetryDelay := 0, clockAhead := 0 }
  /-- The model's state in the current run. -/
  state : State := State.init
  label : String := ""
  /-- True once the current run broke a rule. The rest of that run is
  skipped: after the first difference every later line would differ too. -/
  broken : Bool := false
  runs : Nat := 0
  /-- How many calls were judged and found legal. -/
  events : Nat := 0
  errors : List String := []

/-- Note a problem with line number `n`, and skip the rest of the run. -/
def Verdict.fail (v : Verdict) (n : Nat) (line msg : String) : Verdict :=
  { v with broken := true,
           errors := v.errors ++ [s!"line {n}, run {v.label}: {msg}\n    {line}"] }

/-- Read one line. -/
def Verdict.line (v : Verdict) (n : Nat) (line : String) : Verdict :=
  match line.splitOn " " with
  | [""] => v
  | ["run", label, lease, maxAttempts, maxRetryDelay] =>
    match lease.toNat?, maxAttempts.toNat?, maxRetryDelay.toNat? with
    | some l, some m, some r =>
      -- `clockAhead` is 0: the lease theorems need that, and the judge
      -- moves the true time forward to every clock value it sees.
      { v with cfg := { leaseDuration := l, maxAttempts := m, maxRetryDelay := r, clockAhead := 0 },
               state := State.init, label, broken := false, runs := v.runs + 1 }
    | _, _, _ => v.fail n line "cannot read this line"
  | "ev" :: fields =>
    if v.runs = 0 then v.fail n line "a call before the first run" else
    if v.broken then v else
    match parseEvent fields with
    | none => v.fail n line "cannot read this line"
    | some e =>
      match judgeEvent v.cfg v.state e with
      | .ok s => { v with state := s, events := v.events + 1 }
      | .error msg => v.fail n line msg
  | _ => v.fail n line "cannot read this line"

/-- Judge a whole file. -/
def judgeText (text : String) : Verdict :=
  ((text.splitOn "\n").foldl (fun (v, n) line => (v.line n line, n + 1)) ({}, 1)).1

/-! ## Self-checks

These run on every build. They show that the judge accepts a legal run and
rejects each kind of broken one. Without them, a judge that accepts
everything would go unnoticed. Lease 3, at most 2 attempts, retry delay at
most 5. -/

/-- The judge's errors for a small run. -/
def judgeSample (events : List String) : List String :=
  (judgeText ("\n".intercalate ("run sample 3 2 5" :: events))).errors

-- A legal run: claim, two renewals, an interrupted shutdown, a second
-- attempt that waits for a retry, a third that completes.
#guard judgeSample [
  "ev claim 1 0 0 accepted ok - running 1 0 3",
  "ev renew 1 1 0 accepted ok 3 running 1 0 4",
  "ev renew 1 2 0 accepted error 4 running 1 0 5",
  "ev interrupt 1 0 0 accepted ok - running 1 1 5",
  "ev release 1 0 0 accepted ok - running 1 1 -",
  "ev claim 2 2 0 accepted ok - running 2 1 5",
  "ev delay 2 3 4 accepted ok - running 2 1 7",
  "ev claim 3 7 0 accepted ok - running 3 1 10",
  "ev complete 3 0 0 accepted ok - completed 3 1 -"] = []

-- Broken: the worker writes again after it scheduled a retry.
#guard judgeSample [
  "ev claim 1 0 0 accepted ok - running 1 0 3",
  "ev delay 1 1 1 accepted ok - running 1 0 2",
  "ev complete 1 0 0 accepted ok - completed 1 0 -"] ≠ []

-- Broken: a shutdown adds two interruptions instead of one.
#guard judgeSample [
  "ev claim 1 0 0 accepted ok - running 1 0 3",
  "ev interrupt 1 0 0 accepted ok - running 1 2 3"] ≠ []

-- Broken: a retry delay above the limit.
#guard judgeSample [
  "ev claim 1 0 0 accepted ok - running 1 0 3",
  "ev delay 1 1 6 accepted ok - running 1 0 7"] ≠ []

-- Broken: the worker's deadline (5) is later than the lease it was given (4).
#guard judgeSample [
  "ev claim 1 0 0 accepted ok - running 1 0 3",
  "ev renew 1 1 0 accepted ok 3 running 1 0 4",
  "ev renew 1 2 0 accepted ok 5 running 1 0 5"] ≠ []

-- Broken: a call with an attempt number that no worker was given.
#guard judgeSample [
  "ev claim 1 0 0 accepted ok - running 1 0 3",
  "ev renew 2 1 0 refused stale - running 1 0 3"] ≠ []

end LeaseProof
