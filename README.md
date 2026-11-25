# Eclipse SCINTX

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eclipse-scintx/scintx/badge)](https://scorecard.dev/viewer/?uri=github.com/eclipse-scintx/scintx)

> **S**upply **C**hain **INT**elligence E**X**change — a reusable gateway connecting software registries and consumers with supply-chain security providers.

---

## Overview

The Eclipse SCINTX gateway provides a containerized HTTP service for artifact submission, validation (`purl`, cryptographic `digest`, or raw `content` bytes), persistent status tracking, and health probing.

---

## Quick Start (Local Binary)

Requires [Go 1.26.10+](https://go.dev/dl/).

```bash
make build
./bin/scintx serve
```

Or run the self-contained deterministic demonstration (requires no live provider credentials or network access):

```bash
make demo
```

---

## Container Build and Run

Build the reproducible, non-root container image:

```bash
docker build -t scintx-gateway:latest .
```

Run the container with a mounted `/data` volume for persistent SQLite storage:

```bash
docker run --rm -p 8080:8080 -v scintx-data:/data scintx-gateway:latest
```

To check that the image builds, starts, and reports healthy, run `make image-check`. CI runs the same check on every pull request.

### Container Runtime and Filesystem Requirements

- **Minimal runtime:** Built on `gcr.io/distroless/static-debian12:nonroot` with a statically linked Go binary (`/scintx`).
- **Non-root execution:** Runs as UID/GID `65532:65532` (`nonroot`).
- **Filesystem requirements:**
  - `/scintx`: Read-only gateway executable.
  - `/app/gateway.yaml`: Read-only default gateway configuration.
  - `/data`: Writable directory (owned by `65532:65532`) for the default SQLite database (`file:/data/scintx.db`) and WAL files when using embedded SQLite storage. It also holds uploaded content under `/data/blobs` (`SCINTX_BLOB_DIR`), so it must be writable even when PostgreSQL is configured. The gateway checks this at startup and stops with a clear error if it cannot write there.
  - `/tmp`: Not used. A `multipart/form-data` upload is hashed and written to `/data/blobs` as it streams in. It is never buffered in memory. The container supports `--read-only` root filesystems when `/data` is mounted.

---

## Liveness and Readiness Probes

The gateway exposes HTTP health endpoints and a built-in CLI probe subcommand (`scintx health`) that works inside the distroless image without `curl` or a shell:

- **Liveness (`GET /healthz`):** Returns `200 OK` (`{"status":"ok"}`) when the HTTP server process is alive.
- **Readiness (`GET /readyz`):** Returns `200 OK` (`{"status":"ready"}`) when configuration is loaded, the persistent database (`SQLite` or `PostgreSQL`) responds to a health ping, and the server is ready to accept submissions. Returns `503 Service Unavailable` during graceful shutdown or if storage is unreachable.
- **Container probe command:** `["/scintx", "health"]` (configured as the `Dockerfile` `HEALTHCHECK`).

---

## Configuration and Credential Handling

Configuration values resolve in precedence order (highest to lowest):

1. **Environment variables and mounted `*_FILE` secret files** (e.g., `SCINTX_ADDR`, `SCINTX_INSTANCE_ID`, `SCINTX_DATABASE_URL`, `SCINTX_DATABASE_URL_FILE`, `SCINTX_BLOB_DIR`, `SCINTX_AUTH_BEARER_TOKEN`, `SCINTX_AUTH_BEARER_TOKEN_FILE`)
2. **Gateway configuration file** (`gateway.yaml` or `SCINTX_CONFIG`)
3. **Built-in defaults**

Secrets and database credentials are supplied via environment variables or mounted secret files (`*_FILE`) and are never written into `gateway.yaml` or API responses.

---

## Walkthrough: Submit, Poll Status, and Validation Error

### 1. Submit a valid artifact (`POST /v1/submissions`)

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/submissions \
  -H 'Content-Type: application/json' \
  -d '{"artifact": {"purl": "pkg:npm/lodash@4.17.20"}}'
```

### 2. Poll submission status (`GET /v1/submissions/{id}`)

```bash
curl -sS http://127.0.0.1:8080/v1/submissions/<submission-id>
```

### 3. Validation failure (`HTTP 422 Unprocessable Entity`)

```bash
curl -i -X POST http://127.0.0.1:8080/v1/submissions \
  -H 'Content-Type: application/json' \
  -d '{"artifact": {"purl": "invalid-purl"}}'
```

---

## Persistent Storage, Self-Healing Restart Behavior, and Limitations

- **Persistent state retention (`SQLite` & `PostgreSQL`):** Submissions are persisted via `database/sql` (`internal/gateway/sql_store.go`). By default, the gateway uses a pure-Go embedded SQLite database (`file:data/scintx.db` locally, `file:/data/scintx.db` in containers) with Write-Ahead Logging (`WAL`). For multi-instance deployments, set `SCINTX_DATABASE_URL` (or `SCINTX_DATABASE_URL_FILE`) to a `postgres://...` connection URI.
- **Self-healing restart behavior (no stuck scans):** Work is claimed from the persistent store using time-bounded leases (`lease_until`) and an execution attempt counter (`attempts`). If the gateway restarts or crashes while a submission is in `accepted` or `running` state, the submission is not killed: once its lease expires, the gateway's normal worker loop automatically re-claims and completes it. If a submission repeatedly fails or crashes across `DefaultMaxAttempts` (3 attempts), it automatically transitions to terminal `failed` state (fail-closed) so scans never get stuck and no separate recovery service is required.
- **Retries and deploys:** An attempt that fails with a retryable error is retried after a backoff (5s, then 10s). An attempt that a graceful shutdown cuts short is released at once and does not count toward the 3-attempt limit. The `attempts` field counts every claim; the `interruptions` field counts the ones a shutdown cut short.
- **Uploaded content (`SCINTX_BLOB_DIR`):** The bytes of a `content` upload are streamed to a file in the blob directory (`data/blobs` locally, `/data/blobs` in containers) so provider adapters can read them. An upload uses a small fixed amount of memory, whatever the file size, so many uploads at once do not grow memory. The file is deleted as soon as its submission reaches `completed` or `failed`. It is kept across retries and graceful shutdowns, because the next attempt still needs it. A background sweep (once per minute, and at startup) removes anything a crash left behind.
- **Deployment limitations:**
  - Embedded SQLite supports a single gateway container instance; multi-replica deployments require PostgreSQL (`SCINTX_DATABASE_URL=postgres://...`).
  - Multi-replica deployments must also mount one shared volume as the blob directory on every replica. Otherwise a worker on one replica cannot read a file that another replica received.
  - The blob directory has no size quota. Plan disk space for the largest upload (`gateway.maxContentBytes`, 64 MiB by default) times the number of submissions that can be queued or running at once.
  - Provider adapter execution, aggregation, and policy evaluation are staged in subsequent releases.
  - **The gateway fails closed: no submission can reach `completed` yet.** No provider adapters run in this release, so nothing can scan an artifact. Every valid submission therefore ends as `failed` with the error `no provider adapters are configured; the artifact was not scanned`. It is not retried. The gateway logs a warning about this at startup. A `completed` status will only appear once an adapter has actually run.
  - **Uploaded content is not scanned yet.** The bytes of a `content` upload are stored for the provider adapters, but no adapter runs in this release. So today a submission fails closed at once and its file is deleted right away. The submission record keeps only the SHA-256, size, filename, and media type.
  - **Authentication is off by default.** Set `SCINTX_AUTH_BEARER_TOKEN` (or `SCINTX_AUTH_BEARER_TOKEN_FILE`) before exposing the gateway. The gateway logs a warning at startup when no token is set.

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).
