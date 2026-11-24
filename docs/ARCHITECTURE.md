# SCINTX Architecture (Milestone 1)

This document describes the SCINTX 0.1 architecture defined in issues [#65](https://github.com/eclipse-scintx/scintx/issues/65) through [#75](https://github.com/eclipse-scintx/scintx/issues/75) and implemented for Milestone 1 ([#41](https://github.com/eclipse-scintx/scintx/issues/41)).

---

## 1. Roles and Separation of Responsibilities

- **Gateway Maintainers:** Own the gateway configuration (`gateway.yaml`), provider adapter credentials, and source-controlled YAML policies (`policies/*.yaml`).
- **Consumers (Registries, CI/CD, Researcher Tools):** Submit artifacts (`purl`, `digest`, or raw `content` bytes) and an optional policy ID to the gateway via its HTTPS API or SDKs, poll submission status, and retrieve the **Aggregate Report** and **Policy Report**. Consumers do not configure providers, capabilities, or gateway execution timeouts.

---

## 2. Three-Stage Gateway Pipeline

When a consumer submits an artifact via `POST /v1/submissions`, the gateway executes three stages:

1. **Orchestration (`internal/gateway/select.go` & `runner.go`):**
   - Resolves the requested policy (or `gateway.defaultPolicy`, `baseline-security`).
   - Evaluates each registered `ProviderAdapter` through four selection checks:
     1. Gateway enablement, `supportedSchemaVersion` check, and `CheckAvailability()` (`available`).
     2. Capability intersection with the policy's top-level `capabilities` list (`matched_capabilities`).
     3. Artifact input compatibility against `SupportedInputs` (`eligible`).
     4. Policy `allowlist` and `denylist` filtering (`selected`).
   - Runs selected adapters concurrently within the policy's `evaluationDeadline` and each provider's configured `timeout`.

2. **Aggregation (`api.AggregateReport`):**
   - Captures an immutable snapshot of the submission, gateway configuration revision, resolved policy summary, provider selection outcomes (`providers[]`), execution runs (`providerRuns[]`), and normalized `ProviderReport`s (`providerReports[]`).
   - Findings remain associated with their originating `ProviderReport` rather than being deduplicated.
   - Runs still executing when `evaluationDeadline` expires are recorded with `status: "incomplete"`. Missing or failed evidence is never represented as an empty `findings: []` list.

3. **Policy Evaluation (`internal/policy`):**
   - Evaluates the `AggregateReport` against the policy's `violations` and `annotations` rules.
   - Produces a `PolicyReport` with `policyVerdict` set to:
     - `violated`: One or more violation rules matched.
     - `undetermined`: No violation rules matched, but at least one violation rule lacked completed capability evidence.
     - `satisfied`: All violation rules were conclusively evaluated against completed evidence with zero matches.

---

## 3. HTTP API Endpoints

| Method & Path | Purpose |
|---|---|
| `POST /v1/submissions` | Submit an artifact (`application/json` or `multipart/form-data`) and optional `policy` ID |
| `GET /v1/submissions/{id}` | Poll submission lifecycle status (`accepted`, `running`, `completed`, `failed`) and summary |
| `GET /v1/submissions/{id}/aggregate-report` | Retrieve the immutable `AggregateReport` (`schemaVersion: "1"`) |
| `GET /v1/submissions/{id}/policy-report` | Retrieve the `PolicyReport` (`policyVerdict`, `violations[]`, `annotations[]`) |
| `GET /v1/providers` | Inspect registered provider adapter descriptors and availability status |
| `GET /v1/policies` | Inspect loaded and validated policy definitions |
| `GET /healthz` | Liveness probe (`200 OK` when the gateway process is alive) |
| `GET /readyz` | Readiness probe (`200 OK` when policies and required adapters are ready) |

---

## 4. State Retention, Restart Behavior, and M1 Limitations

- **State retention:** Submissions, Aggregate Reports, Policy Reports, and raw provider evidence are retained in memory (`internal/gateway/store.go`) for the lifetime of the gateway process.
- **Restart behavior:** On `SIGINT`/`SIGTERM`, `/readyz` immediately transitions to `503 Service Unavailable`, the HTTP listener drains, and the orchestrator waits for in-flight provider runs before exiting. Restarting the process clears in-memory state.
- **Initial limitations:** Durable database storage, distributed worker queues, and signed webhook delivery are scheduled for subsequent milestones.
