# Eclipse SCINTX

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/yeeth-security/scintx/badge)](https://scorecard.dev/viewer/?uri=github.com/yeeth-security/scintx)

> **S**upply **C**hain **INT**elligence E**X**change — a reusable gateway, provider adapters, and SDKs connecting software registries and consumers with supply-chain security providers.

---

## Overview

Eclipse SCINTX provides a consistent way to submit software artifacts (`purl`, cryptographic `digest`, or raw `content` bytes) for security assessment and evaluate results against source-controlled policies:

1. **Orchestration:** Selects compatible provider adapters (`osv`, `ossindex`, etc.) based on the active policy's declared `capabilities` and the submitted artifact form.
2. **Aggregation:** Combines normalized **Provider Reports** into an immutable **Aggregate Report** while preserving provider provenance, availability, and execution status (`completed`, `failed`, `timed_out`, `incomplete`).
3. **Policy Evaluation:** Evaluates the Aggregate Report against the selected policy (`baseline-security`) to produce a **Policy Report** with a `satisfied`, `violated`, or `undetermined` verdict.

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
docker build -t scintx-gateway:m1 .
```

Run the container in deterministic demo mode (no live provider credentials required):

```bash
docker run --rm -p 8080:8080 -e SCINTX_DEMO_FIXTURES=1 scintx-gateway:m1
```

### Container Runtime and Filesystem Requirements

- **Minimal runtime:** Built on `gcr.io/distroless/static-debian12:nonroot` with a statically linked Go binary (`/scintx`).
- **Non-root execution:** Runs as UID/GID `65532:65532` (`nonroot`).
- **Filesystem requirements:**
  - `/scintx`: Read-only gateway executable.
  - `/app/gateway.yaml` and `/app/policies/`: Read-only default gateway configuration and YAML policies. Operators may mount custom policies at `/etc/scintx/policies` and set `SCINTX_POLICIES_DIR=/etc/scintx/policies`.
  - `/tmp`: Only used if a `multipart/form-data` upload exceeds the 32 MiB in-memory multipart buffer. The container supports `--read-only` root filesystems when `--tmpfs /tmp:rw,noexec,nosuid,size=128m` is provided.

---

## Liveness and Readiness Probes

The gateway exposes HTTP health endpoints and a built-in CLI probe subcommand (`scintx health`) that works inside the distroless image without `curl` or a shell:

- **Liveness (`GET /healthz`):** Returns `200 OK` (`{"status":"ok"}`) when the HTTP server process is alive.
- **Readiness (`GET /readyz`):** Returns `200 OK` (`{"status":"ready"}`) when configuration and policies are loaded, the server is not shutting down, and all `required: true` providers are available. Returns `503 Service Unavailable` otherwise.
- **Container probe command:** ` ["/scintx", "health"]` (wired as the `Dockerfile` `HEALTHCHECK`).

---

## Configuration and Credentials

Gateway maintainers own configuration (`gateway.yaml`) and policies (`policies/*.yaml`). Values resolve in precedence order (highest to lowest):

1. **Environment variables and mounted `*_FILE` secret files** (e.g., `SCINTX_OSSINDEX_TOKEN_FILE`, `SCINTX_OSSINDEX_TOKEN`, `SCINTX_OSV_BASE_URL`, `SCINTX_AUTH_BEARER_TOKEN`)
2. **Gateway configuration file** (`gateway.yaml` or `SCINTX_CONFIG`)
3. **Built-in defaults**

If an optional provider (`required: false`) is missing credentials (such as `SCINTX_OSSINDEX_TOKEN`), the gateway starts normally and records that provider in the Aggregate Report with `available: false` and `reasons: ["missing_credentials"]`.

---

## Walkthrough: Submit, Poll Status, Reports, and Validation Error

### 1. Submit a valid artifact (`POST /v1/submissions`)

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/submissions \
  -H 'Content-Type: application/json' \
  -d '{
    "artifact": { "purl": "pkg:npm/lodash@4.17.20" },
    "policy": "baseline-security"
  }'
```

### 2. Poll submission status (`GET /v1/submissions/{id}`)

```bash
curl -sS http://127.0.0.1:8080/v1/submissions/<submission-id>
```

### 3. Retrieve Aggregate Report and Policy Report

```bash
curl -sS http://127.0.0.1:8080/v1/submissions/<submission-id>/aggregate-report
curl -sS http://127.0.0.1:8080/v1/submissions/<submission-id>/policy-report
```

### 4. Validation failure (`HTTP 422 Unprocessable Entity`)

```bash
curl -i -X POST http://127.0.0.1:8080/v1/submissions \
  -H 'Content-Type: application/json' \
  -d '{"artifact": {"purl": "invalid-purl"}}'
```

---

## State Retention, Restart Behavior, and M1 Limitations

- **In-memory state retention:** In Milestone 1, the gateway stores submissions, Aggregate Reports, Policy Reports, and raw evidence blobs in an in-memory store for the lifetime of the container process.
- **Restart behavior:** Graceful shutdown (`SIGTERM` / `SIGINT`) stops admitting new requests and waits for in-flight provider runs to finish before exiting. All in-memory submission state is cleared on process or container restart; consumers polling a submission across a gateway restart receive `404 Not Found` and should resubmit.
- **Initial deployment limitations:**
  - Single-instance, in-memory state (no shared database or cross-restart persistence in M1).
  - Policies and gateway configuration are loaded at startup; changes to `gateway.yaml` or `policies/*.yaml` take effect on process restart.
  - Webhook push notifications and cross-submission batching are deferred to later milestones.

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).
