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
- **Whose clock:** On PostgreSQL every lease time comes from the database's clock. A gateway only sends durations ("60 seconds from now"), so gateway clocks that disagree do no harm. SQLite has one gateway host, so it uses that host's clock.
- **Graceful shutdown:** `attempts` is also the fencing token, so it only ever goes up. An attempt that a shutdown cuts short adds one to `interruptions` instead, and the attempt limit is checked against `attempts - interruptions`. Deploys therefore cannot use up a submission's attempts.
- **Uploaded content (`internal/blob/`, `internal/gateway/content.go`):** The bytes of a `content` upload live in a blob store, separate from the database. The rules are:
  - **Streamed, never buffered.** The multipart parser hashes each chunk and writes it to a staging file in the same pass (`internal/server/multipart.go`). Memory per upload is one small copy buffer, whatever the file size.
  - **One blob per submission.** A finished upload is renamed to `<submission-id>.blob` just before the submission row is written, so a worker that claims the row always finds the bytes. One blob has one owner, so deleting it needs no reference counting. Identical uploads are not deduplicated.
  - **Deleted when finished.** The worker deletes the blob right after it saves `completed` or `failed` (`internal/gateway/outcome.go`). The blob is kept across retries and graceful shutdowns. A refused upload is deleted before the HTTP response is sent.
  - **Swept as a safety net.** A sweeper (`internal/gateway/blob_sweep.go`) runs at startup and once per minute. It deletes blobs whose submission is finished, blobs older than 5 minutes that have no submission, and staging files not written for 15 minutes. It never deletes a blob when the database cannot be reached.
  - **Provider access.** A provider adapter reads the bytes as a stream with `Orchestrator.OpenContent(submissionID)`.
  - **Backend.** The only backend today is a local directory (`blob.FileStore`). Gateways that share one database must share that directory. `blob.Store` is an interface, so an object store can be added later without touching the gateway.
- **Subsequent stages:** Provider adapter contracts, initial OSV and OSS Index adapters, and end-to-end provider dispatch and policy evaluation build on this foundation in subsequent stages.
