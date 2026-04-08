FROM golang:1.22-bookworm AS builder
ENV CGO_ENABLED=1
RUN apt-get update && apt-get install -y gcc libc6-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /bin/tass ./cmd/tass

# ─── Runtime image ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      git \
      jq \
      curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /bin/tass /usr/local/bin/tass
COPY --from=builder /app/rules /app/rules
COPY action/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
