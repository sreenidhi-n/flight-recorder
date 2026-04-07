#!/bin/sh
echo "$TASS_GITHUB_PRIVATE_KEY" > /tmp/private-key.pem
chmod 600 /tmp/private-key.pem
export TASS_GITHUB_PRIVATE_KEY_PATH=/tmp/private-key.pem
exec tass serve --addr :8080 --db /data/tass.db
