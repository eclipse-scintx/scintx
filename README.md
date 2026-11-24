# Eclipse SCINTX

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/yeeth-security/scintx/badge)](https://scorecard.dev/viewer/?uri=github.com/yeeth-security/scintx)

> **S**upply **C**hain **INT**elligence E**X**change — a reusable gateway connecting software registries and consumers with supply-chain security providers.

---

## Overview

The Eclipse SCINTX gateway provides a containerized HTTP service for artifact submission, validation (`purl`, cryptographic `digest`, or raw `content` bytes), status tracking, and health probing.

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

Run the container:

```bash
docker run --rm -p 8080:8080 scintx-gateway:latest
```

### Container Runtime and Filesystem Requirements

- **Minimal runtime:** Built on `gcr.io/distroless/static-debian12:nonroot` with a statically linked Go binary (`/scintx`).
- **Non-root execution:** Runs as UID/GID `65532:65532` (`nonroot`).
- **Filesystem requirements:**
  - `/scintx`: Read-only gateway executable.
  - `/app/gateway.yaml`: Read-only default gateway configuration.
  - `/tmp`: Only used if a `multipart/form-data` upload exceeds the 32 MiB in-memory multipart buffer. The container supports `--read-only` root filesystems when `--tmpfs /tmp:rw,noexec,nosuid,size=128m` is provided.

---

## Liveness and Readiness Probes

The gateway exposes HTTP health endpoints and a built-in CLI probe subcommand (`scintx health`) that works inside the distroless image without `curl` or a shell:

- **Liveness (`GET /healthz`):** Returns `200 OK` (`{"status":"ok"}`) when the HTTP server process is alive.
- **Readiness (`GET /readyz`):** Returns `200 OK` (`{"status":"ready"}`) when configuration is loaded and the server is ready to accept submissions. Returns `503 Service Unavailable` during graceful shutdown.
- **Container probe command:** `["/scintx", "health"]` (configured as the `Dockerfile` `HEALTHCHECK`).

---

## Configuration and Credential Handling

Configuration values resolve in precedence order (highest to lowest):

1. **Environment variables and mounted `*_FILE` secret files** (e.g., `SCINTX_ADDR`, `SCINTX_INSTANCE_ID`, `SCINTX_AUTH_BEARER_TOKEN`, `SCINTX_AUTH_BEARER_TOKEN_FILE`)
2. **Gateway configuration file** (`gateway.yaml` or `SCINTX_CONFIG`)
3. **Built-in defaults**

Secrets and credentials are supplied via environment variables or mounted secret files (`*_FILE`) and are never written into `gateway.yaml` or responses.

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

## State Retention, Restart Behavior, and Limitations

- **In-memory state retention:** The gateway stores submissions in an in-memory store (`internal/gateway/store.go`) for the lifetime of the container process.
- **Restart behavior:** Graceful shutdown (`SIGTERM` / `SIGINT`) marks `/readyz` as `503 Service Unavailable`, drains active HTTP connections, and waits for in-flight submissions to finish before exiting. All in-memory submission state is cleared on process or container restart; consumers polling a submission across a gateway restart receive `404 Not Found` and should resubmit.
- **Deployment limitations:**
  - Single-instance, in-memory state (no shared database or cross-restart persistence).
  - Provider adapter execution, aggregation, and policy evaluation are staged in subsequent releases.

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).
