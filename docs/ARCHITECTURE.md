# Eclipse SCINTX Architecture — Initial Gateway

This document describes the initial containerized Eclipse SCINTX gateway.

---

## 1. Scope of the Initial Gateway

The initial gateway establishes the core HTTP entrypoint, artifact validation, in-memory submission lifecycle, configuration and secret loading, and container health probing:

- **Artifact Validation (`api/types.go`, `api/purl.go`):**
  - Accepts `purl` (canonicalized Package URL), cryptographic `digest` (`sha256`, `sha384`, `sha512`), or raw `content` bytes (`multipart/form-data`, including `.vsix` manifest PURL extraction).
  - Rejects empty or malformed artifacts with `422 Unprocessable Entity` (`application/problem+json`).
- **Submission Lifecycle (`internal/gateway/`):**
  - `POST /v1/submissions` creates a `Submission` (`schemaVersion: "1"`) in `accepted` state and transitions it through `running` to `completed`.
  - `GET /v1/submissions/{id}` returns the current submission status (`accepted`, `running`, `completed`, `failed`).
- **Health & Readiness Probes (`internal/server/`, `cmd/scintx/health.go`):**
  - `GET /healthz`: Liveness probe (`200 OK` while the gateway process is alive).
  - `GET /readyz`: Readiness probe (`200 OK` when ready; `503 Service Unavailable` during shutdown).
  - `scintx health`: Built-in CLI health probe used by the distroless container `HEALTHCHECK`.

---

## 2. State Retention, Restart Behavior, and Limitations

- **State retention:** Submissions are stored in memory (`internal/gateway/store.go`) for the lifetime of the gateway process.
- **Restart behavior:** On `SIGINT`/`SIGTERM`, `/readyz` transitions to `503 Service Unavailable`, the HTTP listener drains, and the orchestrator waits for in-flight submissions before exiting. Restarting the container clears all in-memory submissions.
- **Subsequent stages:** Provider adapter contracts, initial OSV and OSS Index adapters, and end-to-end provider dispatch and policy evaluation build on this foundation in subsequent stages.
