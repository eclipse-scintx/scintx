# Eclipse SCINTX

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/yeeth-security/scintx/badge)](https://scorecard.dev/viewer/?uri=github.com/yeeth-security/scintx)

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

### Container Runtime and Filesystem Requirements

- **Minimal runtime:** Built on `gcr.io/distroless/static-debian12:nonroot` with a statically linked Go binary (`/scintx`).
- **Non-root execution:** Runs as UID/GID `65532:65532` (`nonroot`).
- **Filesystem requirements:**
  - `/scintx`: Read-only gateway executable.
  - `/app/gateway.yaml`: Read-only default gateway configuration.
  - `/data`: Writable directory (owned by `65532:65532`) for the default SQLite database (`file:/data/scintx.db`) and WAL files when using embedded SQLite storage.
  - `/tmp`: Only used if a `multipart/form-data` upload exceeds the 32 MiB in-memory multipart buffer. The container supports `--read-only` root filesystems when `/data` is mounted (or PostgreSQL is configured) and `--tmpfs /tmp:rw,noexec,nosuid,size=128m` is provided.

---

## Liveness and Readiness Probes

The gateway exposes HTTP health endpoints and a built-in CLI probe subcommand (`scintx health`) that works inside the distroless image without `curl` or a shell:

- **Liveness (`GET /healthz`):** Returns `200 OK` (`{"status":"ok"}`) when the HTTP server process is alive.
- **Readiness (`GET /readyz`):** Returns `200 OK` (`{"status":"ready"}`) when configuration is loaded, the persistent database (`SQLite` or `PostgreSQL`) responds to a health ping, and the server is ready to accept submissions. Returns `503 Service Unavailable` during graceful shutdown or if storage is unreachable.
- **Container probe command:** `["/scintx", "health"]` (configured as the `Dockerfile` `HEALTHCHECK`).

---

## Configuration and Credential Handling

Configuration values resolve in precedence order (highest to lowest):

1. **Environment variables and mounted `*_FILE` secret files** (e.g., `SCINTX_ADDR`, `SCINTX_INSTANCE_ID`, `SCINTX_DATABASE_URL`, `SCINTX_DATABASE_URL_FILE`, `SCINTX_AUTH_BEARER_TOKEN`, `SCINTX_AUTH_BEARER_TOKEN_FILE`)
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
- **Deployment limitations:**
  - Embedded SQLite supports a single gateway container instance; multi-replica deployments require PostgreSQL (`SCINTX_DATABASE_URL=postgres://...`).
  - Provider adapter execution, aggregation, and policy evaluation are staged in subsequent releases.

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).
