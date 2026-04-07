#!/bin/sh
set -e
# Write the GitHub App private key from env var to a temp file.
# Fly.io secrets can't be mounted as files directly.
if [ -n "$TASS_GITHUB_PRIVATE_KEY" ]; then
    echo "$TASS_GITHUB_PRIVATE_KEY" > /app/private-key.pem
    chmod 600 /app/private-key.pem
    export TASS_GITHUB_PRIVATE_KEY_PATH=/app/private-key.pem
fi
exec tass serve --addr :8080 --db /data/tass.db
