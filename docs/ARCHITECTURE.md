# Eclipse SCINTX Architecture — Initial Gateway

This document describes the initial containerized Eclipse SCINTX gateway.

---

## 1. Scope of the Initial Gateway

The initial gateway establishes the core HTTP entrypoint, artifact validation, persistent submission lifecycle (`SQLite` and `PostgreSQL`), configuration and secret loading, and container health probing:

- **Artifact Validation (`api/types.go`, `api/purl.go`):**
  - Accepts **exclusively one** artifact form per submission: `purl` (canonicalized Package URL), cryptographic `digest` (`sha256`, `sha384`, `sha512`), or raw `content` bytes (`multipart/form-data`).
  - Rejects empty, malformed, or multi-type artifacts with `422 Unprocessable Entity` (`application/problem+json`).
- **Submission Lifecycle & Persistent Storage (`internal/gateway/`):**
  - `POST /v1/submissions` creates a `Submission` (`schemaVersion: "1"`) in `accepted` state and transitions it through `running` to `completed` once a provider adapter has finished. With no adapter installed (the case in this release) nothing can scan the artifact, so the submission fails closed: it ends as `failed` with a public reason and is not retried.
  - `GET /v1/submissions/{id}` returns the current submission status (`accepted`, `running`, `completed`, `failed`).
  - Submissions are persisted via `database/sql` (`internal/gateway/sql_store.go`) using either pure-Go SQLite (`modernc.org/sqlite`, default `file:data/scintx.db`) or PostgreSQL (`github.com/jackc/pgx/v5`, via `postgres://...` DSN).
- **Health & Readiness Probes (`internal/server/`, `cmd/scintx/health.go`):**
  - `GET /healthz`: Liveness probe (`200 OK` while the gateway process is alive).
  - `GET /readyz`: Readiness probe (`200 OK` when ready and the database responds to `Ping`; `503 Service Unavailable` during shutdown or storage outage).
  - `scintx health`: Built-in CLI health probe used by the distroless container `HEALTHCHECK`.

---

## 2. State Retention, Self-Healing Restart Behavior, and Limitations

- **State retention:** Submissions are stored in SQLite (`file:data/scintx.db` or `/data/scintx.db` in containers) or PostgreSQL (`SCINTX_DATABASE_URL=postgres://...`) and survive process and container restarts.
- **Self-healing restart behavior (recovery by design):** Instead of fire-and-forget goroutines or a separate startup recovery service, the `Orchestrator` claims work from the `submissions` table using a lease timestamp (`lease_until`) and an `attempts` counter (`ClaimNextSubmission`). Any `accepted` or `running` submission whose lease has expired is automatically picked back up and completed by the normal worker loop after a gateway restart. Submissions that exhaust `DefaultMaxAttempts` (3) transition to terminal `failed` state so scans can never get stuck.
- **Retry backoff:** An attempt that fails with `ErrRetryable` is not retried at once. The worker moves `lease_until` into the future (5s, then 10s), so the lease doubles as a "not before" timer and no extra column is needed. This uses `DelayRetry`, the one call that may also move a lease earlier (a retry delay is often shorter than the rest of the lease).
- **Lease renewals only move forward:** A heartbeat calls `RenewLease`, which keeps the later of the stored lease and the new one. So a renewal that arrives late can never shorten a lease.
- **Whose clock:** On PostgreSQL every lease time comes from the database's clock. A gateway only sends durations ("60 seconds from now"), so gateway clocks that disagree do no harm. The memory store keeps the monotonic stopwatch, same as the worker, so a wall-clock step does not expire a live lease. SQLite stores a wall-clock timestamp, and the worker stops when that wall time passes as well as when its stopwatch does. Two hosts must not share one SQLite file: their wall clocks can disagree.
- **Graceful shutdown:** `attempts` is also the fencing token, so it only ever goes up. An attempt that a shutdown cuts short adds one to `interruptions` instead, and the attempt limit is checked against `attempts - interruptions`. Deploys therefore cannot use up a submission's attempts.
- **Uploaded content (`internal/blob/`, `internal/gateway/content.go`):** The bytes of a `content` upload live in a blob store, separate from the database. The rules are:
  - **Streamed, never buffered.** The multipart parser hashes each chunk and writes it to a staging file in the same pass (`internal/server/multipart.go`). Memory per upload is one small copy buffer, whatever the file size.
  - **One blob per submission.** A finished upload is renamed to `<submission-id>.blob` just before the submission row is written, so a worker that claims the row always finds the bytes. One blob has one owner, so deleting it needs no reference counting. Identical uploads are not deduplicated.
  - **Deleted when finished.** The worker deletes the blob right after it saves `completed` or `failed` (`internal/gateway/outcome.go`). The blob is kept across retries and graceful shutdowns. A refused upload is deleted before the HTTP response is sent.
  - **Swept as a safety net.** A sweeper (`internal/gateway/blob_sweep.go`) runs at startup and once per minute. It deletes blobs whose submission is finished, blobs older than 5 minutes that have no submission, and staging files not written for 15 minutes. It never deletes a blob when the database cannot be reached.
  - **Provider access.** A provider adapter reads the bytes as a stream with `Orchestrator.OpenContent(submissionID)`.
  - **Backend.** The only backend today is a local directory (`blob.FileStore`). Gateways that share one database must share that directory. `blob.Store` is an interface, so an object store can be added later without touching the gateway.
- **Subsequent stages:** Provider adapter contracts, initial OSV and OSS Index adapters, and end-to-end provider dispatch and policy evaluation build on this foundation in subsequent stages.

---

## 3. Formal Verification of the Lease Architecture

The lease and fencing design is checked by machine. The proofs are written in Lean 4 and live in `formal/`. They use no library beyond Lean itself, so they build in seconds.

Run `./scripts/formal.sh` to check them. It builds every proof and then fails if a main theorem has a hole. It needs Lean 4 (install with [elan](https://lean-lang.org/install/)); the exact version is pinned in `formal/lean-toolchain`. CI runs the same script in its `formal` job.

### 3.1 What is modelled

- **One submission row** with the four fields the lease logic uses: `status`, `attempts`, `interruptions`, `lease_until`. Each `Store` method is one function in `formal/LeaseProof/Store.lean`.
- **Any number of workers**, on any number of gateways. Each step of a worker is one `Action` in `formal/LeaseProof/Model.lean`.
- **Failures.** The model allows stale clock readings, a crash at any point, an answer that gets lost after the write landed, a renewal that lands long after its sender gave up on it, and a final write long after the lease ran out. One more failure can be switched on: a clock that runs fast (`clockAhead`).

A theorem about "every reachable state" covers every possible run: any length, any order of events, any number of workers.

### 3.2 What is proven

**With any clocks and any network** (`Safety.lean`). These protect the stored result.

| Theorem | Meaning |
|---|---|
| `fencing` | A worker whose attempt number is not the current one cannot change the row. |
| `fenced_stays` | Once a newer attempt exists, the old worker is shut out for good. |
| `late_renewal_is_fenced` | A write that arrives late with an old attempt number changes nothing. |
| `late_renewal_never_shortens` | A renewal that arrives late never moves a lease earlier. |
| `tokens_unique`, `at_most_one_writer` | No two workers ever have the same attempt number. So at most one worker can write. |
| `terminal_is_final` | `completed` and `failed` never change again. |
| `attempts_monotone` | `attempts` never goes down. |
| `attempt_budget` | `attempts - interruptions` never exceeds `maxAttempts`. |

**When no clock runs fast** (`LeaseSafety.lean`). Lost answers and late renewals are allowed here.

| Theorem | Meaning |
|---|---|
| `one_lease_holder` | At most one worker holds a lease that has not run out. |
| `lease_holder_is_owner` | That worker owns the newest attempt, and the row is still `running`. |
| `lease_holder_can_complete` | A worker that finishes within its lease is never refused. |

**Also when no clock runs fast** (`LeaseBound.lean`, `Progress.lean`).

| Theorem | Meaning |
|---|---|
| `lease_is_bounded` | A lease never ends later than one lease duration, or one retry delay, from now. |
| `never_stuck` | After that wait, any idle worker can claim an unfinished row. The claim starts a new attempt or marks the row `failed`. |

### 3.3 Limits

These are proven too, as example runs in `Limits.lean`. In both, the old worker is fenced, so the stored result stays correct. What can happen is duplicate work.

1. **Two workers can run the same submission at once, even with perfect clocks.** A worker only notices a lost lease on its next heartbeat, and a hook needs time to stop. So calls to a provider can happen twice. **Provider adapters must be safe to repeat.**
2. **A fast clock breaks the lease.** If one party reads a time that is ahead of the others, it can claim a row whose lease is still running. How much this matters depends on the store:
   - **PostgreSQL:** every lease time comes from the database's clock, and gateways only send durations. So gateway clocks that disagree cannot cause this. What remains: the database clock must not jump forward, and a gateway's clock must not tick slower than the database's (a worker checks its own lease with its own stopwatch).
   - **SQLite:** the lease is a wall-clock timestamp, and the worker stops when that wall time passes, not only when its stopwatch does. A step of the wall clock on that host cannot leave a worker running on an expired lease. It is not safe to share one SQLite file between hosts.

A third limit was found by the proofs and then fixed: a renewal that arrived late could move a lease back. Renewals now only move forward. `late_renewal_no_longer_breaks_the_lease` replays the old failing run and shows that it is harmless.

### 3.4 How the model is tied to the Go code

A proof about a model says nothing if the code behaves differently. So the code is checked against the model by machine. This is done in two directions, one for the stores and one for the workers.

**The stores: the model writes, Go replays.** The model prints test scenarios (`formal/LeaseProof/Vectors.lean`): 85 lists of store calls, and after each call the row that the model expects. They are printed by the very functions the theorems are about, and stored in `internal/gateway/testdata/lease_vectors.json`.

`TestLeaseVectorsMemory`, `TestLeaseVectorsSQLite` and `TestLeaseVectorsPostgres` replay every scenario against the real stores and compare after each call (`internal/gateway/lease_vectors_test.go`). `./scripts/formal.sh` rewrites the file, and CI fails when it is out of date. On PostgreSQL the lease follows the database clock, so that test compares whether a lease is set, not its exact time, and it skips the scenarios where a claim arrives at the exact moment a lease ends.

**The workers: Go runs, the model judges.** The model says what a worker *may* do, not what it *will* do, so nothing can be generated for the worker code. Instead `TestWorkerTracesFollowTheModel` (`internal/gateway/trace_test.go`) runs the real workers through 15 situations: success, retries, errors, panics, timeouts, a slow store, lost leases, a frozen worker, deploys, and random faults (dropped calls and lost answers). It records every store call. Then the model's own `step` function judges the recording (`formal/LeaseProof/TraceCheck.lean`): is each recorded run a run that the model allows?

The proofs rest on five rules about worker behaviour. The judge checks all of them:

| Worker rule | How the judge catches a break |
|---|---|
| Every write carries the attempt number of the worker's own claim. | The model's worker for that number is not in a phase that makes this call. |
| After a refusal or a final write, the worker writes nothing more. | The same. |
| The worker's own lease deadline is never later than the stored lease. | The heartbeat passes its deadline to each renewal (as the context deadline). It must not be later than the model's. |
| A shutdown adds exactly one to `interruptions`. | The model's row and the real row differ. |
| A retry delay never exceeds the limit. | The model refuses the delay, so the rows differ. |

Each rule was broken on purpose in the Go code once, and the judge rejected the run each time. This test needs Lean, so plain `go test` skips its last step when Lean is not installed. `./scripts/formal.sh` and the CI `formal` job always run it.

### 3.5 What the proofs do not cover

- **The Go code itself.** The proofs are about the model. The checks in 3.4 show that the stores and the workers follow the model in every scenario that was tried. That is strong evidence, but it is testing, not proof: a run that no scenario produces is not covered.
- **The mapping from a store call to a model action.** The judge must decide which model action a recorded call stands for. That table (`Event.actions` in `TraceCheck.lean`, about 20 lines) is checked by reading.
- **A deadline that is later than the stored lease by less than one step of the clock.** The worker trace test sees times as the wall clock reports them.
- **The PostgreSQL clock arithmetic.** The model has plain numbers for time. That the SQL adds a duration to the database clock correctly is covered by tests, not by the proofs.
- **Atomic store methods.** The model treats each `Store` method as one step. The Go stores get this from a mutex, a single `UPDATE`, or a transaction.
- **A gateway clock that jumps backwards.** The model assumes that the clock readings of one worker never go back.
- **That a worker comes along.** `never_stuck` says a claim will work. It cannot promise that a gateway is running.
- **Queue order.** The model has one row, so it says nothing about which row is claimed first.
- **Blob storage.**
