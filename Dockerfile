# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.25-bookworm AS builder

# CGO is required for Tree-sitter (C grammar bindings).
ENV CGO_ENABLED=1

# Install GCC for CGO compilation.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache module downloads separately from source.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .
ARG VERSION=docker
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /bin/tass ./cmd/tass

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# CA certificates for HTTPS calls to GitHub API.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security.
RUN useradd -m -u 1001 tass

COPY --from=builder /bin/tass /usr/local/bin/tass

# Tree-sitter rule files (data, not code).
COPY --from=builder /app/rules /app/rules
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

USER tass
WORKDIR /app

EXPOSE 8080

CMD ["/bin/sh", "/app/docker-entrypoint.sh"]
