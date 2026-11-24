# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Both base images are pinned by digest. A tag such as "1.26.10-bookworm" can
# be re-pointed to a different image at any time. A digest cannot, so the
# build always uses exactly these bytes. Dependabot keeps the digests fresh
# (see the "docker" entry in .github/dependabot.yml).

# Stage 1: Reproducible static binary build.
FROM golang:1.26.10-bookworm@sha256:5de7c99eb78ca5e515a4c340235d0955ec5964a5071c492c15503d7c267da473 AS builder

# The target OS and CPU type. BuildKit and Podman fill these in from
# "--platform" (for example linux/arm64). They are empty with older builders,
# so the build step below falls back to linux/amd64. Before this, amd64 was
# hard-coded and an arm64 image got an amd64 binary that could not run.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Download module dependencies first for layer caching.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source and build a reproducible static binary.
COPY . .
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/scintx ./cmd/scintx && \
    mkdir -p /out/data

# Stage 2: Minimal distroless runtime running as non-root (UID/GID 65532).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

WORKDIR /app

# Copy compiled gateway binary, default read-only configuration, and writable /data dir.
COPY --from=builder /out/scintx /scintx
COPY --from=builder /src/gateway.yaml /app/gateway.yaml
COPY --from=builder --chown=65532:65532 /out/data /data

# Default to persistent SQLite database under /data (override with SCINTX_DATABASE_URL).
ENV SCINTX_DATABASE_URL="file:/data/scintx.db"

# Keep uploaded content under /data too (override with SCINTX_BLOB_DIR).
# The gateway creates this directory at startup. A blob lives here only until
# its submission is finished, so the directory is empty when the gateway is idle.
ENV SCINTX_BLOB_DIR="/data/blobs"

# Run as non-root user (65532:65532).
USER 65532:65532

VOLUME ["/data"]
EXPOSE 8080

# Built-in health probe works inside distroless without curl or a shell.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/scintx", "health"]

ENTRYPOINT ["/scintx"]
CMD ["serve"]
