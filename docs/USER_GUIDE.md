# TASS User Guide

> Complete reference for the CLI, GitHub App, slash commands, and hosted dashboard.

---

## Table of Contents

1. [What TASS Does](#what-tass-does)
2. [Installation](#installation)
3. [CLI Commands](#cli-commands)
   - [tass init](#tass-init)
   - [tass scan](#tass-scan)
   - [tass policy](#tass-policy)
   - [tass seed](#tass-seed)
   - [tass serve](#tass-serve)
   - [tass version](#tass-version)
4. [CLI Workflow: End to End](#cli-workflow-end-to-end)
5. [Exporting Local Scans to the Dashboard](#exporting-local-scans-to-the-dashboard)
6. [GitHub App Setup](#github-app-setup)
7. [Slash Commands (PR Comments)](#slash-commands-pr-comments)
8. [Verification UI](#verification-ui)
9. [Dashboard & Audit Trail](#dashboard--audit-trail)
10. [.tassignore](#tassignore)
11. [GitHub Action (Air-Gap Mode)](#github-action-air-gap-mode)
12. [Environment Variables Reference](#environment-variables-reference)

---

## What TASS Does

TASS scans source code for **capabilities** — things your code can now DO that it couldn't before:

- New external dependencies (packages, modules)
- Outbound HTTP/network calls
- Database operations
- Filesystem reads and writes
- Privilege escalation patterns
- AI/ML framework usage (boto3, Strands Agents, FastMCP, OpenTelemetry)

It compares newly detected capabilities against a committed manifest (`tass.manifest.yaml`). Anything not in the manifest is **novel** and requires explicit human review.

TASS has two independent modes:

| Mode | What it does | Needs a server? |
|---|---|---|
| **CLI** | Local scans, policy generation | No |
| **GitHub App** | Auto-scans every PR, posts comments, hosts verify UI | Yes (Fly.io) |

---

## Installation

### Prerequisites

- Go 1.22+ with `CGO_ENABLED=1`
- Xcode Command Line Tools (macOS): `xcode-select --install`
- Git

### Build and install

```bash
# Clone the TASS source
git clone https://github.com/sreenidhi-n/flight-recorder
cd flight-recorder

# Install the binary to your PATH
go build -o ~/go/bin/tass ./cmd/tass

# Verify
tass version
```

The binary has detection rules embedded — no `--rules-dir` flag needed anywhere.

---

## CLI Commands

### tass init

Scans the entire repository and writes `tass.manifest.yaml` as a capability baseline. Run once when first adopting TASS on a repo.

```
tass init [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--path` | `.` | Path to the repo root to scan |
| `--rules-dir` | `./rules` | Custom rules directory (uses embedded rules if this dir doesn't exist) |

**Examples:**

```bash
# Baseline the current repo
tass init

# Baseline a repo at a different path
tass init --path ~/code/my-service
```

**Output:** Creates `tass.manifest.yaml` in the repo root. Shows a count of Layer 0 (dependency) and Layer 1 (AST) detections.

**Next step:** Commit `tass.manifest.yaml` to version control.

```bash
git add tass.manifest.yaml
git commit -m "chore: add TASS capability baseline"
```

---

### tass scan

Scans for capabilities introduced since the last manifest update by diffing HEAD against a base branch. This is the main command you run during development.

```
tass scan [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--base` | `main` | Base branch to diff against |
| `--format` | `text` | Output format: `text` or `json` |
| `--path` | `.` | Path to the repo root |
| `--rules-dir` | `./rules` | Custom rules directory |
| `--ci` | `false` | Emit GitHub Actions `::warning::` annotations to stderr |
| `--export-to` | _(empty)_ | URL of a TASS server to push results to (see [Exporting](#exporting-local-scans-to-the-dashboard)) |
| `--token` | _(empty)_ | API token for `--export-to` (or set `TASS_IMPORT_TOKEN` env var) |
| `--repo` | _(auto)_ | `owner/repo` for export (auto-detected from git remote) |
| `--branch` | _(auto)_ | Branch name for export (auto-detected from git HEAD) |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | No novel capabilities detected |
| `1` | Novel capabilities found (expected signal for CI gates) |
| `1` | Operational error (manifest missing, git not available, etc.) |

**Examples:**

```bash
# Scan against main (default)
tass scan

# Scan against a different base branch
tass scan --base develop

# Machine-readable output for scripting
tass scan --format json

# CI mode — also emit GitHub Actions annotations
tass scan --format json --ci

# Scan and push results to the hosted dashboard
tass scan \
  --export-to https://tass-test.fly.dev/api/import \
  --token $TASS_IMPORT_TOKEN

# Explicitly specify repo + branch for export
tass scan \
  --export-to https://tass-test.fly.dev/api/import \
  --token $TASS_IMPORT_TOKEN \
  --repo owner/my-service \
  --branch feature/add-stripe
```

**What happens if there's no manifest?**
TASS prints a clear error and tells you to run `tass init` first. It does not silently skip.

---

### tass policy

Generates security policy artifacts from the confirmed capabilities in `tass.manifest.yaml`. Does not require a server or internet connection.

```
tass policy [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | `k8s` | Policy format: `k8s` (Kubernetes NetworkPolicy) or `iam` (AWS IAM) |
| `--app` | `myapp` | App name — used as `podSelector` label (k8s) or `Sid` prefix (IAM) |
| `--namespace` | `default` | Kubernetes namespace (k8s only) |
| `--output` | _(stdout)_ | Write output to this file instead of stdout |
| `--path` | `.` | Path to the repo containing `tass.manifest.yaml` |

**Examples:**

```bash
# Generate a Kubernetes NetworkPolicy and print to stdout
tass policy --format k8s --app payments-service

# Write to a file
tass policy --format k8s --app payments-service --output k8s-netpol.yaml

# Generate an AWS IAM policy
tass policy --format iam --app ai-support-bot

# Write IAM policy to file
tass policy --format iam --app ai-support-bot --output iam-policy.json

# Different namespace
tass policy --format k8s --app myapp --namespace production --output netpol.yaml
```

**K8s output:** A `NetworkPolicy` that allows DNS egress (always) and HTTPS egress (port 443) for each detected network capability. Capability names appear as comments.

**IAM output:** An IAM policy JSON with `Allow` statements for each detected AWS service (mapped from `boto3.client(...)` calls). Includes a `_tass_note` reminding you to narrow `Resource` ARNs before deploying.

> **Important:** Both policy types are starting points, not production-ready. Always review and narrow before deploying.

---

### tass seed

Inserts realistic demo data into a SQLite database for dashboard previewing. Safe to run on a local dev database — will skip silently if demo data is already present (idempotent).

```
tass seed [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--db` | `tass.db` | Path to the SQLite database to seed |

**Examples:**

```bash
# Seed the default local database
tass seed

# Seed a specific database
tass seed --db /tmp/demo.db

# Seed the remote Fly.io database (via SSH)
fly ssh console --app tass-test
tass seed --db /data/tass.db
```

**What gets inserted:**
- 1 installation (`acme-corp`)
- 2 repositories (`payments-service`, `ai-support-bot`)
- 5 scan results with varying capability counts
- 15–20 verification decisions (confirms and reverts) by `alice`, `bob`, and `carol`
- Timestamps spanning the last 2 weeks

---

### tass serve

Starts the TASS web server. This is the **server-only command** — you never run this locally for CLI usage. It requires all GitHub App credentials as environment variables.

```
tass serve [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--addr` | `:8080` | TCP address to listen on |
| `--db` | `tass.db` | Path to the SQLite database |

**Required environment variables** (see [full reference](#environment-variables-reference)):

```bash
TASS_GITHUB_APP_ID
TASS_GITHUB_CLIENT_ID
TASS_GITHUB_CLIENT_SECRET
TASS_GITHUB_WEBHOOK_SECRET
TASS_GITHUB_PRIVATE_KEY_PATH   # or TASS_GITHUB_PRIVATE_KEY (base64)
TASS_SESSION_SECRET
TASS_BASE_URL
```

**Example (local development of TASS itself):**

```bash
source .env.local
./tass serve --db ./dev.db --addr :8080
```

For production deployment, see [GitHub App Setup](#github-app-setup).

---

### tass version

```bash
tass version
# tass v3.0.0 (commit abc1234, built 2026-04-08T10:00:00Z)
```

Also accepts `-v` or `--version`.

---

## CLI Workflow: End to End

Here is the complete flow for using TASS on any repository locally:

```bash
# 1. Go to any git repository
cd ~/code/my-service

# 2. Create the baseline (first time only)
tass init
git add tass.manifest.yaml && git commit -m "chore: add TASS baseline"

# 3. Do your work on a branch
git checkout -b feature/add-payment-api
# ... write code ...
git add . && git commit -m "feat: add Stripe integration"

# 4. Scan for new capabilities
tass scan --base main

# 5. If you're happy with what was detected, accept it into the baseline
tass init
git add tass.manifest.yaml && git commit -m "chore: update TASS manifest"

# 6. Generate infra policies from the manifest
tass policy --format k8s --app my-service --output k8s-netpol.yaml
tass policy --format iam --app my-service --output iam-policy.json
```

No internet connection, no GitHub App, no server required for any of these steps.

---

## Exporting Local Scans to the Dashboard

If you want local CLI scans to appear on the hosted verification dashboard (so your team can click Confirm/Revert without leaving the browser), use `--export-to`.

### Setup

The server owner (whoever runs `tass serve` / deploys to Fly.io) must set a token:

```bash
# On Fly.io
fly secrets set TASS_IMPORT_TOKEN="$(openssl rand -hex 32)" --app tass-test
fly deploy --app tass-test
```

Share that token with developers who will use `--export-to`.

### Usage

```bash
# Set token once in your shell profile
export TASS_IMPORT_TOKEN="the-shared-token"

# Scan and export in one command
tass scan \
  --export-to https://tass-test.fly.dev/api/import \
  --token $TASS_IMPORT_TOKEN

# Or rely on the env var (--token not needed)
tass scan --export-to https://tass-test.fly.dev/api/import
```

**What happens:**
1. TASS runs a local scan as usual
2. Detected novel capabilities are POSTed to `/api/import` (no source code — only structured capability data)
3. The server stores them as a pending scan
4. TASS prints: `→ Review & verify on TASS: https://tass-test.fly.dev/verify/cli-...`
5. Click the link, log in with GitHub, confirm/revert

`--repo` and `--branch` are auto-detected from your git remote and HEAD. Override them if needed:

```bash
tass scan \
  --export-to https://tass-test.fly.dev/api/import \
  --repo sreenidhi-n/my-service \
  --branch feature/add-stripe
```

---

## GitHub App Setup

The GitHub App mode automatically scans every PR — no `tass scan` command needed by developers.

### 1. Create the GitHub App

Go to **GitHub → Settings → Developer Settings → GitHub Apps → New GitHub App**.

| Field | Value |
|---|---|
| Name | `TASS` (or `tass-yourname`) |
| Homepage URL | `https://your-tass-url.fly.dev` |
| Webhook URL | `https://your-tass-url.fly.dev/webhooks/github` |
| Webhook secret | Any strong random string (save this) |

**Permissions required:**

| Permission | Level |
|---|---|
| Contents | Read & Write |
| Pull requests | Read & Write |
| Checks | Read & Write |
| Metadata | Read |
| Members | Read |

**Subscribe to events:**

- [x] Pull request
- [x] Issue comments ← required for slash commands

### 2. Deploy to Fly.io

```bash
cd flight-recorder

# Create app and volume
fly apps create tass-yourname
fly volumes create tass_data --region iad --size 1 --app tass-yourname

# Set secrets
fly secrets set \
  TASS_GITHUB_APP_ID="your-app-id" \
  TASS_GITHUB_CLIENT_ID="your-client-id" \
  TASS_GITHUB_CLIENT_SECRET="your-client-secret" \
  TASS_GITHUB_WEBHOOK_SECRET="your-webhook-secret" \
  TASS_SESSION_SECRET="$(openssl rand -hex 32)" \
  TASS_BASE_URL="https://tass-yourname.fly.dev" \
  TASS_IMPORT_TOKEN="$(openssl rand -hex 32)" \
  --app tass-yourname

# Set the private key
fly secrets set TASS_GITHUB_PRIVATE_KEY="$(cat your-app.pem)" --app tass-yourname

# Deploy
fly deploy --app tass-yourname
```

### 3. Install the App on a Repository

Go to your GitHub App's settings page → **Install App** → choose the repos you want scanned.

After installation, TASS:
1. Scans the default branch to establish an initial manifest (if none exists)
2. Opens a PR with the manifest if anything is found
3. Starts scanning every new PR automatically

---

## Slash Commands (PR Comments)

Once the GitHub App is installed and has scanned a PR, developers can verify capabilities directly from the PR comment thread without opening the TASS UI.

### Syntax

Post a regular comment (not a review comment) on the PR:

```
/tass confirm all
```
```
/tass revert all
```
```
/tass confirm 1,2,3
```
```
/tass revert 4,5
```
```
/tass confirm 1,2 revert 3
```

The numbers map to the `#` column in the TASS capability table in the PR comment. Commands are case-insensitive.

### What happens

1. TASS receives the comment webhook
2. Checks that the commenter has **write or admin** access to the repository
3. Maps the numbers to capability IDs (using the order from the PR comment table)
4. Records each decision (same as clicking Confirm/Revert in the UI)
5. Updates the PR comment with a progress table
6. Replies with a summary:

```
✅ Processed: confirmed #1, #2, #3 · reverted #4
View full details: https://tass-test.fly.dev/verify/scan-abc123
```

### Prerequisites

The GitHub App must subscribe to **Issue comments** events (set in GitHub App settings → Permissions & Events). If you don't see TASS responding to `/tass` commands, check this setting.

---

## Verification UI

The verification UI is the web page where developers confirm or revert each detected capability. It is accessible at:

```
https://your-tass-url.fly.dev/verify/{scan-id}
```

The link appears in the PR comment TASS posts automatically.

### Features

- Each capability card shows the detected code, file location, category badge, and confidence score
- **Confirm** — you intended this capability; it will be added to the manifest
- **Revert** — you did not intend this; the GitHub Check will be marked `action_required`
- **Optional note** — type a justification before clicking Confirm or Revert
- Progress bar shows how many of N capabilities have been reviewed
- After every decision the PR comment updates live with a per-row status table

### Live PR comment updates

After each individual decision (not just when all are done), the PR comment updates to show:

```
## TASS — 3/5 Capabilities Reviewed

> ✅ 2 confirmed · ↩️ 1 reverted · ⏳ 2 pending

| # | Capability           | Category      | Status       |
|---|----------------------|---------------|--------------|
| 1 | stripe-go v76        | 📦 Dependency | ✅ Confirmed |
| 2 | net/http.Post        | 🌐 Network    | ↩️ Revert   |
| 3 | sql.Open             | 🗄️ Database  | ✅ Confirmed |
| 4 | os.WriteFile         | 📁 Filesystem | ⏳ Pending   |
| 5 | boto3.client         | 🌐 Network    | ⏳ Pending   |

Continue reviewing on TASS → https://...
```

---

## Dashboard & Audit Trail

### Dashboard

```
https://your-tass-url.fly.dev/dashboard
```

Requires GitHub login. Shows:
- Stat cards: total scans, capabilities, confirms, reverts across all repos
- Recent scans table with status pills (`pending` / `verified`)
- Per-repo drill-down with full stats, developer breakdown, and generated policies

### Audit Trail

```
https://your-tass-url.fly.dev/audit/{repo_id}
```

Full chronological log of every verification decision and manifest commit. Supports:
- Date range filtering (`?from=2026-01-01&to=2026-12-31`)
- CSV export: `GET /api/audit/export?repo_id=X&from=Y&to=Z`
- JSON API: `GET /api/audit?repo_id=X&from=Y&to=Z`

### Policy download (from dashboard)

The repo drill-down page shows generated K8s and IAM policies with copy and download buttons. The same data is available via API:

```
GET /api/policy?repo_id=X&format=k8s    → YAML
GET /api/policy?repo_id=X&format=iam    → JSON
```

---

## .tassignore

Exclude files and directories from scanning using `.gitignore` syntax. Create `.tassignore` in the repo root:

```gitignore
# Vendored code
vendor/
node_modules/
.venv/

# Test files
*_test.go
**/*.spec.js
**/*.spec.py

# Generated code
*.pb.go
*_templ.go

# Specific directory
internal/testdata/
```

**Supported patterns:**

| Pattern | Effect |
|---|---|
| `vendor/` | Ignore everything under `vendor/` |
| `*.test.js` | Ignore all `.test.js` files |
| `**/*.spec.py` | Ignore `.spec.py` files in any subdirectory |
| `!important.go` | Un-ignore `important.go` even if a previous rule matched it |
| `# comment` | Ignored |

`.tassignore` is respected by `tass init`, `tass scan`, and the GitHub App webhook pipeline.

---

## GitHub Action (Air-Gap Mode)

Use the TASS GitHub Action when you want scans to run entirely within your own CI infrastructure — no code leaves your network.

### Basic usage

Create `.github/workflows/tass.yml` in your repo:

```yaml
name: TASS Security Scan
on: [pull_request]

jobs:
  tass:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: sreenidhi-n/flight-recorder/action@main
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `manifest-path` | `tass.manifest.yaml` | Path to the manifest |
| `rules-dir` | `/app/rules` | Path to rules (pre-built in Docker image) |
| `base-ref` | `${{ github.base_ref }}` | Base branch to diff against |
| `export-to` | _(empty)_ | Hybrid mode: URL to push results to hosted dashboard |
| `export-token` | _(empty)_ | Token for `export-to` |
| `fail-on-novel` | `true` | Exit `1` (fail CI) when novel capabilities are found |

### Outputs

| Output | Description |
|---|---|
| `novel-count` | Number of novel capabilities detected |

### Hybrid mode (air-gap scan + cloud dashboard)

```yaml
- uses: sreenidhi-n/flight-recorder/action@main
  with:
    export-to: https://tass-test.fly.dev/api/import
    export-token: ${{ secrets.TASS_IMPORT_TOKEN }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    PR_NUMBER: ${{ github.event.pull_request.number }}
```

Scans locally (no code leaves CI), but pushes only the structured `CapabilitySet` (no source code) to the dashboard so your team can verify via the UI.

### GitHub Actions annotations

With `--ci` flag (used automatically by the action), TASS emits inline warnings on the PR diff:

```
::warning file=payment/client.go,line=42::TASS: novel capability "HTTP client outbound request (Post)" (network_access)
```

These appear as yellow warning markers directly on the changed lines in the GitHub PR Files Changed view.

---

## Environment Variables Reference

### Server (`tass serve`)

| Variable | Required | Description |
|---|---|---|
| `TASS_GITHUB_APP_ID` | ✓ | GitHub App numeric ID |
| `TASS_GITHUB_CLIENT_ID` | ✓ | OAuth client ID (for user login) |
| `TASS_GITHUB_CLIENT_SECRET` | ✓ | OAuth client secret |
| `TASS_GITHUB_WEBHOOK_SECRET` | ✓ | HMAC secret for webhook signature verification |
| `TASS_GITHUB_PRIVATE_KEY_PATH` | ✓* | Path to RSA `.pem` private key file |
| `TASS_GITHUB_PRIVATE_KEY` | ✓* | Base64-encoded private key (alternative to path) |
| `TASS_SESSION_SECRET` | ✓ | 32+ byte random string for signing session cookies |
| `TASS_BASE_URL` | ✓ | Public URL, e.g. `https://tass-test.fly.dev` |
| `TASS_IMPORT_TOKEN` | — | Token for `POST /api/import` (CLI export feature). Disabled if unset. |

*One of `TASS_GITHUB_PRIVATE_KEY_PATH` or `TASS_GITHUB_PRIVATE_KEY` is required.

### CLI (`tass scan --export-to`)

| Variable | Description |
|---|---|
| `TASS_IMPORT_TOKEN` | API token for `--export-to`. Equivalent to `--token` flag. |

---

*TASS — Trusted AI Security Scanner. Machines state facts. Humans state intent.*
