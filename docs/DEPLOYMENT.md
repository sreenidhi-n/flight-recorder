# TASS Deployment Guide

This guide covers deploying TASS to [Fly.io](https://fly.io) — the recommended production target. Total cost: **under $5/month**.

---

## Architecture

TASS is a **single Go binary** with:
- **SQLite** on a Fly.io persistent volume (no external database)
- **GitHub API** for all repo interactions (no git clone, no agent runner)
- **Fly.io** for compute, TLS, and global routing

```
Fly.io Machine (shared-cpu-1x, $3.19/mo)
  └── /data/tass.db  ← SQLite on persistent volume ($0.15/mo)
```

---

## Prerequisites

1. [Fly.io account](https://fly.io/app/sign-up) (free tier works for launch)
2. [flyctl CLI](https://fly.io/docs/hands-on/install-flyctl/) installed and authenticated
3. A GitHub App registered (see Step 1 below)
4. A domain pointed at Fly.io (optional for custom domain)

---

## Step 1: Register the GitHub App

Before deploying, create your GitHub App:

1. Go to `https://github.com/settings/apps/new`
2. Fill in:
   - **GitHub App name:** `TASS Security` (or your brand name)
   - **Homepage URL:** Your Fly.io app URL (e.g., `https://tass-security.fly.dev`)
   - **Webhook URL:** `https://<your-fly-app>.fly.dev/webhooks/github`
   - **Webhook secret:** Generate with `openssl rand -hex 32`
3. Set **Repository permissions:**
   - Contents: Read & Write
   - Pull requests: Read & Write
   - Checks: Read & Write
   - Metadata: Read-only
4. Subscribe to **Events:**
   - Pull request
   - Installation
5. Click **Create GitHub App**
6. Note your **App ID**
7. Click **Generate a private key** → download the `.pem` file
8. Under OAuth, note **Client ID** and generate a **Client secret**
9. Set the **Callback URL** to `https://<your-fly-app>.fly.dev/auth/github/callback`

---

## Step 2: Clone and Initialize

```bash
git clone https://github.com/tass-security/tass.git
cd tass

# Initialize Fly.io app (fly.toml is already included)
fly launch --copy-config --name tass-security --region iad
# When asked "Would you like to set up a Postgresql database?": No
# When asked "Would you like to set up an Upstash Redis database?": No
```

---

## Step 3: Create the Persistent Volume

```bash
fly volumes create tass_data \
  --region iad \
  --size 1        # 1GB — sufficient for thousands of scans
```

---

## Step 4: Set Secrets

```bash
# Upload the private key content as a secret
fly secrets set \
  TASS_GITHUB_APP_ID="<your_app_id>" \
  TASS_GITHUB_CLIENT_ID="<your_client_id>" \
  TASS_GITHUB_CLIENT_SECRET="<your_client_secret>" \
  TASS_GITHUB_WEBHOOK_SECRET="<your_webhook_secret>" \
  TASS_SESSION_SECRET="$(openssl rand -hex 32)"

# Upload private key file
fly secrets set TASS_GITHUB_PRIVATE_KEY_PATH=/app/private-key.pem

# Add the private key content itself
# (we use a workaround: store the key content in a secret and write it at startup)
# See "Private Key Handling" below for the recommended approach.
```

### Private Key Handling (Recommended)

The cleanest approach is to store the private key content as a secret and mount it via a startup script. Add to your `fly.toml`:

```toml
[env]
  TASS_GITHUB_PRIVATE_KEY_PATH = "/app/private-key.pem"
```

Then create a `docker-entrypoint.sh`:
```bash
#!/bin/sh
# Write the private key from the environment secret to disk
echo "$TASS_GITHUB_PRIVATE_KEY" > /app/private-key.pem
chmod 600 /app/private-key.pem
exec tass serve --addr :8080 --db /data/tass.db
```

Set the key content as a secret:
```bash
fly secrets set TASS_GITHUB_PRIVATE_KEY="$(cat /path/to/your-app.pem)"
```

---

## Step 5: Set TASS_BASE_URL

```bash
# Use your actual Fly.io URL or custom domain
fly secrets set TASS_BASE_URL="https://tass-security.fly.dev"

# Or with custom domain:
fly secrets set TASS_BASE_URL="https://app.tass.dev"
```

---

## Step 6: Deploy

```bash
fly deploy
```

The multi-stage Dockerfile builds the binary with CGO (for Tree-sitter), then creates a slim runtime image. First build: ~3–5 minutes. Subsequent builds: ~1 minute.

---

## Step 7: Verify Deployment

```bash
# Check the app is running
fly status

# Check health endpoint
curl https://tass-security.fly.dev/health
# → {"status":"ok","service":"tass"}

# Tail logs
fly logs
```

---

## Step 8: Configure Branch Protection (Optional but Recommended)

In each repository's Settings → Branches → Branch protection rules:

1. Add a rule for your default branch (`main` or `master`)
2. Enable **"Require status checks to pass before merging"**
3. Add `TASS` to the required status checks

This ensures PRs cannot be merged until TASS either:
- Confirms all capabilities (check passes), or
- Developer explicitly reverts unintended capabilities (check stays failing — intentionally blocking merge)

---

## Custom Domain

```bash
fly certs add app.tass.dev
fly ips allocate-v4

# Update DNS: A record pointing app.tass.dev → <Fly.io IPv4>
```

---

## Backups with Litestream (Recommended for Production)

[Litestream](https://litestream.io) continuously replicates your SQLite database to S3, giving zero data loss if the Fly volume dies.

1. Create an S3 bucket (or use Tigris via Fly)
2. Add `litestream.yml`:
```yaml
dbs:
  - path: /data/tass.db
    replicas:
      - type: s3
        bucket: your-tass-backups
        path: tass.db
```
3. Update `Dockerfile` CMD to: `litestream replicate -exec "tass serve --addr :8080 --db /data/tass.db"`

---

## Scaling

TASS is designed for a single instance with SQLite. This handles:
- ~100 concurrent scans (each takes <5 seconds)
- Thousands of repositories
- All webhook traffic from GitHub

When you outgrow single-instance SQLite (likely past $1M ARR):
- Scale vertically (Fly performance machines)
- Migrate to Fly's managed Postgres
- Or use [Turso](https://turso.tech) for distributed SQLite

---

## Environment Variable Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `TASS_GITHUB_APP_ID` | ✅ | GitHub App numeric ID |
| `TASS_GITHUB_CLIENT_ID` | ✅ | OAuth Client ID |
| `TASS_GITHUB_CLIENT_SECRET` | ✅ | OAuth Client Secret |
| `TASS_GITHUB_WEBHOOK_SECRET` | ✅ | HMAC secret for webhook validation |
| `TASS_GITHUB_PRIVATE_KEY_PATH` | ✅ | Path to RSA private key `.pem` |
| `TASS_SESSION_SECRET` | ✅ | 32+ random bytes for cookie signing |
| `TASS_BASE_URL` | ✅ | Public root URL (e.g. `https://app.tass.dev`) |

---

## Monitoring

TASS emits structured logs via `log/slog` (JSON in production). Fly.io forwards these to its built-in log aggregation.

- **Logs:** `fly logs` or connect to Fly's Grafana integration
- **Health check:** `GET /health` → `{"status":"ok","service":"tass"}`
- **Metrics:** Future — `GET /metrics` endpoint planned for v3.1

---

## Updating

```bash
git pull
fly deploy   # Zero-downtime rolling deploy
```

Fly.io does a rolling deploy: the new machine starts and is health-checked before the old one stops. Downtime: 0 seconds.

---

## Rollback

```bash
fly releases list           # List recent deployments
fly deploy --image <image>  # Roll back to a specific image
```
