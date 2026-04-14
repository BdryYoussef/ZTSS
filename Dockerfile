# ── Stage 1: builder ──────────────────────────────────────────────────────────
#
# Uses the official Go image to compile the ztss-server binary.
# CGO is disabled so the output is a fully static binary — compatible with
# the minimal distroless runtime image in Stage 2.
#
# wiki/architecture_overview.md: Go 1.22+ mandatory.
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copy dependency manifests first — leverages Docker layer cache so
# `go mod download` is skipped on source-only changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy full source tree.
COPY . .

# Build the combined node+API binary.
# -trimpath removes local file paths from stack traces (security hygiene).
# -ldflags="-s -w" strips debug symbols to reduce image size (~30%).
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /bin/ztss-server \
    ./cmd/ztss-node/...

# Pre-create /data with UID 65532 (distroless nonroot) so Docker volume mounts
# inherit the correct permissions and FileSystemStore.Put can write files.
RUN mkdir -p /data && chown -R 65532:65532 /data

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
#
# distroless/static: no shell, no package manager, minimal attack surface.
# The binary is completely static so no libc is needed.
FROM gcr.io/distroless/static:nonroot

# /data is the default FileSystem BlockStore path (ZTSS_STORAGE_DIR default).
# Copy the pre-chowned skeleton from the builder so volume mounts start with
# the correct UID 65532 ownership and FileSystemStore.Put can write files.
COPY --from=builder --chown=65532:65532 /data /data

VOLUME ["/data"]

# P2P node port (ZTSS_ADDR).
EXPOSE 7001
# REST API port (ZTSS_API_ADDR) — exposed only on node-1 in compose.
EXPOSE 8080

COPY --from=builder /bin/ztss-server /ztss-server

# Run as nonroot (UID 65532) — distroless default.
USER nonroot

ENTRYPOINT ["/ztss-server"]
