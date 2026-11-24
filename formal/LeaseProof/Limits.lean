/-
Copyright (c) 2026 Contributors to the Eclipse Foundation

SPDX-License-Identifier: EPL-2.0
-/
import LeaseProof.Safety
import LeaseProof.LeaseSafety

/-!
# Limits: what the lease architecture does NOT guarantee

A proof is only useful if we also know where it stops. Each theorem below is
a concrete run of the model that shows one limit. They are proven, not
assumed: Lean replays the run and checks the final state.

1. Two workers CAN run the same submission at the same time, even with
   perfect clocks. The lease cannot stop this. Fencing makes it harmless for
   the stored result.
2. If a gateway's clock runs ahead, two workers CAN hold an unexpired lease
   at the same time. So `one_lease_holder` really needs `clockAhead = 0`.
   On PostgreSQL the store uses the database's clock, so this cannot happen
   there. It can with SQLite, if two gateways with different clocks were
   ever to share one database file.

A third limit, a renewal that lands late, was found here and is fixed. Its
example run is kept at the end of this file, now with the opposite result.

In every run the stored result stays safe, because the old worker is fenced
as soon as the new attempt exists. What is NOT protected is anything a
worker does outside the store, such as sending the file to a provider. That
can happen twice.
-/

namespace LeaseProof

/-- A small example setup: leases last 3 time units. No clock is fast. -/
def demo : Config :=
  { leaseDuration := 3, maxAttempts := 3, maxRetryDelay := 5, clockAhead := 0 }

/-- The same setup, but a gateway's clock may run 3 time units ahead. -/
def demoSkewed : Config := { demo with clockAhead := 3 }

/-- **Limit 1: two workers can run the same submission at once.**

The run: worker 0 claims the row at time 0. Its lease ends at time 3. Worker
0 is slow to notice (it only checks on its next heartbeat). At time 3 the
lease is over, so worker 1 claims the row.

Now both are executing. This happens with perfect clocks, so no lease
design can prevent it. It is the reason fencing exists: worker 0 is fenced
(its token is older than the row's), so by `fencing` it cannot write. -/
theorem two_workers_can_run_at_once :
    ∃ s, Reachable demo s ∧
      (s.workers 0).phase = .executing ∧ (s.workers 1).phase = .executing ∧
      fenced s 0 :=
  ⟨run demo State.init [.claim 0 0, .tick 3, .claim 1 3],
    Reachable.init.run _, by decide, by decide, by unfold fenced; decide⟩

/-- **The late result is refused.**

The same run goes on: worker 0 finishes its work and tries to save
"completed". The store refuses it, and the row still belongs to worker 1's
attempt. Then worker 1 saves "completed", and that is accepted. -/
theorem late_result_is_refused :
    let both := run demo State.init [.claim 0 0, .tick 3, .claim 1 3]
    let afterOld := step demo both (.complete 0)
    let afterNew := step demo afterOld (.complete 1)
    afterOld.row = both.row ∧ afterOld.row.status = .running ∧
      afterNew.row.status = .completed := by
  decide

/-- **Limit 2: a clock that runs ahead breaks the lease.**

The run: worker 0 claims the row at true time 0. Its lease ends at time 3.
Worker 1 is on a gateway whose clock shows 3 when the true time is still 0.
It asks the store for work and sends "now = 3". The store compares the lease
with that value, sees an expired lease, and hands the row over.

Both workers now hold a lease that has not run out. So `one_lease_holder`
is false without the assumption `clockAhead = 0`. Worker 0 is fenced. -/
theorem clock_skew_allows_two_lease_holders :
    ∃ s, Reachable demoSkewed s ∧ holdsLease s 0 ∧ holdsLease s 1 ∧ fenced s 0 :=
  ⟨run demoSkewed State.init [.claim 0 0, .claim 1 3],
    Reachable.init.run _, by unfold holdsLease; decide, by unfold holdsLease; decide,
    by unfold fenced; decide⟩

/-- **A former limit, now fixed: a renewal that lands late.**

`RenewLease` used to SET the lease to "sent time + duration". An old
renewal that arrived after a newer one then moved the lease BACK, and an
earlier version of this file proved that two workers could hold the lease
at once because of it. Renewals are forward-only now.

This is the very run that broke the lease before. Worker 0 claims at time
0 (lease ends at 3). At time 1 it sends a renewal that gets stuck. At time
2 it renews again, and this one works: the lease and the worker's deadline
are now 5. Then the stuck renewal from time 1 lands. It asks for 4, and the
lease stays at 5. So at time 4 worker 1 gets nothing. -/
theorem late_renewal_no_longer_breaks_the_lease :
    let s := run demo State.init
      [.claim 0 0, .tick 2, .renew 0 2, .lateRenew 1 1, .tick 2, .claim 1 4]
    s.row.lease = some 5 ∧ s.row.attempts = 1 ∧ (s.workers 1).phase = .idle := by
  decide

end LeaseProof
