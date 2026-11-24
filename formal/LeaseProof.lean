/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Store
import LeaseProof.StoreLemmas
import LeaseProof.Worker
import LeaseProof.Model
import LeaseProof.Reachable
import LeaseProof.Invariant
import LeaseProof.StepCases
import LeaseProof.Step
import LeaseProof.Effects
import LeaseProof.Tokens
import LeaseProof.Safety
import LeaseProof.Lease
import LeaseProof.LeaseSafety
import LeaseProof.LeaseBound
import LeaseProof.Progress
import LeaseProof.Limits
import LeaseProof.Audit
import LeaseProof.Vectors
import LeaseProof.TraceFile

/-!
# Formal verification of the SCINTX lease architecture

This is the entry point. Building it checks every proof in the project.

Read the files in this order:

1. `Store.lean`       the row and the store rules (mirrors `store.go`)
2. `Worker.lean`,
   `Model.lean`       the workers and every event that can happen
3. `Reachable.lean`   what "every state the system can reach" means
4. `Invariant.lean`   facts that are always true, and
   `Step.lean`        the proof that every event keeps them true
5. `Safety.lean`      fencing, final states, attempt budget (no clocks needed)
6. `LeaseSafety.lean` one lease holder at a time (needs: no clock runs fast)
7. `Progress.lean`    a row cannot stay blocked
8. `Limits.lean`      what is NOT guaranteed, shown by example runs
9. `Audit.lean`       prints what each main theorem rests on
10. `Vectors.lean`    prints test scenarios that the Go tests replay against
                      the real stores, to check that the code follows the model
11. `TraceCheck.lean`,
    `TraceFile.lean`  judge runs recorded from the real Go workers: is each
                      one a run that the model allows?

The other files hold helper lemmas for these.

The list of proven theorems, with their plain-language meaning and the
assumptions behind them, is in `docs/ARCHITECTURE.md`.
-/
