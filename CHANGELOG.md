# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Blob storage for `content` uploads (`SCINTX_BLOB_DIR` / `storage.blobDir`,
  default `data/blobs`). Uploads are streamed to disk with constant memory,
  kept only until their submission is `completed` or `failed`, and swept
  after a crash.
- Containerized HTTP gateway (`scintx serve`) with `POST /v1/submissions`,
  `GET /v1/submissions/{id}`, `/healthz`, `/readyz`, and the built-in
  `scintx health` probe for distroless containers.
- Fail-closed validation for exclusive artifact inputs (`purl`, structured
  `digest` with `algorithm` and `value`, or streamed `content` upload).
- Persistent SQLite and PostgreSQL submission stores (`SCINTX_DATABASE_URL`)
  with lease-based work claiming, exponential retry backoff, and concurrent
  worker pool (`SCINTX_WORKERS`).
- Optional inbound Bearer token authentication (`SCINTX_AUTH_BEARER_TOKEN`
  and `*_FILE` secret mounts).
- JSON Schema 2020-12 documents (`schema/`), deterministic offline demo
  (`make demo`), and CI workflows.
- EPL-2.0 license.

### Security

- Fail closed when no provider adapter is configured. Before, a submission
  reached `completed` although nothing had scanned it. Now it ends as
  `failed` with the error `no provider adapters are configured; the artifact
  was not scanned`, and it is not retried. `completed` will only appear once
  an adapter has really run.
- Require Go 1.26.10 (was 1.26.0) to pick up the fix for the compromised
  eMudhra intermediate CA keys (Oct 2026). CI reads the version from `go.mod`.
- The `configRevision` log value no longer includes the database DSN, which
  can hold a password.
- Bearer authentication now accepts the `Bearer` scheme in any letter case
  (RFC 7235).
- Hash bearer tokens with SHA-256 before `subtle.ConstantTimeCompare` so
  authentication timing does not leak the configured token length.

### Changed

- Lease renewals only move a lease forward, so a heartbeat that arrives late
  can no longer shorten it. Retry backoff uses the new `Store.DelayRetry`.
- On PostgreSQL, lease times come from the database clock. Gateways only
  send durations, so gateway clocks that disagree no longer matter.
- Updated `ArtifactInput` to use structured `Digest` (`algorithm` and `value`),
  `contentMeta` JSON key, and `OpenContent` stream reader callback (#68, #70).

[Unreleased]: https://github.com/eclipse-scintx/scintx/commits/HEAD
