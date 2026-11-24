# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

# Stage 1: Reproducible static binary build.
FROM golang:1.26.10-bookworm AS builder

WORKDIR /src

# Download module dependencies first for layer caching.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source and build a reproducible static binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/scintx ./cmd/scintx

# Stage 2: Minimal distroless runtime running as non-root (UID/GID 65532).
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy compiled gateway binary and default read-only configuration/policies.
COPY --from=builder /out/scintx /scintx
COPY --from=builder /src/gateway.yaml /app/gateway.yaml
COPY --from=builder /src/policies /app/policies

# Run as non-root user (65532:65532).
USER 65532:65532

EXPOSE 8080

# Built-in health probe works inside distroless without curl or a shell (#41).
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/scintx", "health"]

ENTRYPOINT ["/scintx"]
CMD ["serve"]
