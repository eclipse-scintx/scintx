/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.TraceFile

/-!
# The program that judges recorded worker runs

The Go test `TestWorkerTracesFollowTheModel` calls it like this, from the
`formal/` folder:

    lake env lean --run JudgeTraces.lean <trace file>

It exits with 0 when every recorded run is a run that the model allows. It
prints each broken rule and exits with 1 otherwise. The judging itself is
in `LeaseProof/TraceCheck.lean` and `LeaseProof/TraceFile.lean`.

This file is not part of the `LeaseProof` library, because `Vectors.lean`
there already has a `main`. A library can only hold one.
-/

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] =>
    let verdict := LeaseProof.judgeText (← IO.FS.readFile path)
    for problem in verdict.errors do
      IO.eprintln problem
    -- An empty file must not count as a pass.
    if verdict.events = 0 then
      IO.eprintln "the trace file holds no calls to judge"
      return 1
    if !verdict.errors.isEmpty then
      return 1
    IO.println s!"the model allows all {verdict.runs} runs ({verdict.events} store calls)"
    return 0
  | _ =>
    IO.eprintln "usage: lake env lean --run JudgeTraces.lean <trace file>"
    return 2
