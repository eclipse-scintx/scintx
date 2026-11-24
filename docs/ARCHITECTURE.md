# Eclipse SCINTX Architecture — Initial Gateway

This document describes the initial containerized Eclipse SCINTX gateway.

---

## 1. Scope of the Initial Gateway

The initial gateway establishes the core HTTP entrypoint, artifact validation, persistent submission lifecycle (`SQLite` and `PostgreSQL`), configuration and secret loading, and container health probing:

- **Artifact Validation (`api/types.go`, `api/purl.go`):**
  - Accepts **exclusively one** artifact form per submission: `purl` (canonicalized Package URL), cryptographic `digest` (`sha256`, `sha384`, `sha512`), or raw `content` bytes (`multipart/form-data`).
  - Rejects empty, malformed, or multi-type artifacts with `422 Unprocessable Entity` (`application/problem+json`).
- **Submission Lifecycle & Persistent Storage (`internal/gateway/`):**
  - `POST /v1/submissions` creates a `Submission` (`schemaVersion: "1"`) in `accepted` state and transitions it through `running` to `completed`.
  - `GET /v1/submissions/{id}` returns the current submission status (`accepted`, `running`, `completed`, `failed`).
  - Submissions are persisted via `database/sql` (`internal/gateway/sql_store.go`) using either pure-Go SQLite (`modernc.org/sqlite`, default `file:data/scintx.db`) or PostgreSQL (`github.com/jackc/pgx/v5`, via `postgres://...` DSN).
- **Health & Readiness Probes (`internal/server/`, `cmd/scintx/health.go`):**
  - `GET /healthz`: Liveness probe (`200 OK` while the gateway process is alive).
  - `GET /readyz`: Readiness probe (`200 OK` when ready and the database responds to `Ping`; `503 Service Unavailable` during shutdown or storage outage).
  - `scintx health`: Built-in CLI health probe used by the distroless container `HEALTHCHECK`.

---

## 2. State Retention, Restart Behavior, and Limitations

- **State retention:** Submissions are stored in SQLite (`file:data/scintx.db` or `/data/scintx.db` in containers) or PostgreSQL (`SCINTX_DATABASE_URL=postgres://...`) and survive process and container restarts.
- **Restart behavior:** On `SIGINT`/`SIGTERM`, `/readyz` transitions to `503 Service Unavailable`, the HTTP listener drains, the orchestrator waits for in-flight submissions, and the database connection closes cleanly.
- **Subsequent stages:** Provider adapter contracts, initial OSV and OSS Index adapters, and end-to-end provider dispatch and policy evaluation build on this foundation in subsequent stages.
