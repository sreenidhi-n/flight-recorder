# TASS — Cursor Implementation Guide

> **You are the Principal Architect for TASS (Trusted AI Security Scanner).**
> Read this file before every task. It is the single source of truth.

## What TASS Is

A GitHub App that scans every pull request for newly introduced capabilities (new dependencies, HTTP calls, database writes, filesystem access, privilege patterns), diffs them against a committed `tass.manifest.yaml`, and surfaces novel capabilities for explicit Confirm/Revert decisions via a hosted web UI. When all capabilities are decided, TASS commits the updated manifest to the PR branch and updates the GitHub Check.

## Stack

- **Language:** Go (single binary)
- **UI:** Templ templates + HTMX (zero JS framework)
- **CSS:** Custom design system (NO Pico CSS — we are removing it)
- **DB:** SQLite via `modernc.org/sqlite`, WAL mode
- **AST:** Tree-sitter via `github.com/smacker/go-tree-sitter` with CGO
- **GitHub:** GitHub App with JWT auth, webhooks, Checks API, Contents API
- **Deploy:** Fly.io (single region, `fly.toml` in repo root)
- **Rules:** `.scm` Tree-sitter query files + `.meta.yaml` sidecars in `rules/`

## File Map

```
cmd/tass/main.go             CLI entrypoint (serve, init, scan, version, seed)
cmd/tass/init.go             tass init — scan repo, generate manifest
cmd/tass/scan.go             tass scan — diff against manifest, report novel caps
cmd/tass/serve.go            tass serve — start HTTP server
cmd/tass/seed.go             [TO CREATE] tass seed — insert demo data

internal/auth/               GitHub OAuth + cookie sessions
internal/github/app.go       GitHub App: JWT, installation tokens
internal/github/checks.go    GitHub Checks API
internal/github/comments.go  PR comment create/update
internal/github/commit.go    Commit manifest to PR branch
internal/github/events.go    Webhook event types
internal/github/fetch.go     Fetch files from GitHub
internal/github/firstrun.go  Installation.created → scan + open setup PR
internal/github/handler.go   Webhook HTTP handler
internal/github/pipeline.go  Full scan pipeline
internal/github/verifier.go  Decision engine → manifest commit → check update
internal/github/webhook.go   Webhook signature verification

internal/scanner/            Layer 0 dep diff + Layer 1 AST scanning
internal/server/             HTTP server, routing, rate limiting, API handlers
internal/server/audit.go     [TO CREATE] GET /api/audit handler
internal/storage/storage.go  SQLite store
internal/storage/migrations/ SQL migrations (001-003 exist, 004 to create)

internal/ui/handlers.go      UI page handlers
internal/ui/ui.go            UI router
internal/ui/static/style.css [TO REPLACE] CSS design system
internal/ui/templates/       Templ files (layout, index, dashboard, verify, setup)
internal/ui/templates/audit.templ [TO CREATE]

pkg/contracts/contracts.go   Shared types
pkg/manifest/manifest.go     Manifest YAML read/write/diff
rules/                       Tree-sitter .scm + .meta.yaml rule files
```

## Design System (replacing Pico CSS)

Remove Pico CSS entirely. Custom CSS:
- System font stack; JetBrains Mono for code
- CSS custom properties with automatic dark mode via `prefers-color-scheme`
- Max-width: 1040px
- Category badge pills: Dependency=purple, Network=blue, Database=orange, Filesystem=green, Privilege=red
- Cards: white bg, 0.5px border, 12px radius
- Tables: bordered containers, rounded corners
- Stat cards: secondary bg, no border, large number + small label
- Code evidence inline (not in `<details>`)
- Thin 4px progress bar
- Status pills: pending=orange, verified=green

---

# IMPLEMENTATION TASKS

Complete in order. After each: `go build ./cmd/tass && go test ./...`

---

## Task 1: Fix critical bugs

**Files:** `internal/storage/storage.go`, `internal/ui/templates/verify.templ`, `internal/github/firstrun.go`, `.gitignore`

1. Add `FullName string` to `ScanResult` in storage.go
2. In `GetScan()` and `GetScansByRepo()`, JOIN repositories to populate FullName
3. In verify.templ, use `d.Scan.FullName` instead of broken `repoFullName()` helper
4. In `SaveDecision()`, use `INSERT OR REPLACE` instead of plain `INSERT`
5. In firstrun.go `processRepo()`, also fetch + AST-scan source files (not just dep files)
6. Add `.DS_Store`, `.history/` to `.gitignore`

**Done test:** Verify page "View PR" link works. Double-clicking Confirm doesn't error.

---

## Task 2: Replace CSS design system

**Files:** `internal/ui/static/style.css`, `internal/ui/templates/layout.templ`

1. Replace style.css entirely with new design system
2. Remove Pico CSS CDN `<link>` from layout.templ (keep HTMX)
3. New topbar: magnifying glass SVG + "TASS" left, Dashboard link + avatar + @username + logout right
4. Clean footer: centered 12px "TASS — Trusted AI Security Scanner"

**Done test:** New design loads. Dark mode works. No Pico CSS.

---

## Task 3: Redesign verify page

**Files:** `internal/ui/templates/verify.templ`

1. Header: "PR #N — branch-name", subtitle with repo + "View PR on GitHub ↗"
2. Thin 4px progress bar with "X of Y reviewed" label
3. Cards: colored category pills, monospace file locations, inline code evidence, Confirm/Revert buttons on right. Decided cards: colored left border + icon + "by @username" at reduced opacity
4. Success banner ABOVE card list when all decided
5. Fix HTMX OOB swap for progress bar + success banner

**Done test:** Full HTMX verify flow works. Progress updates. Success banner at top.

---

## Task 4: Redesign dashboard

**Files:** `internal/ui/templates/dashboard.templ`, `internal/storage/storage.go`, `internal/ui/handlers.go`

1. Add `GetRecentScans(ctx, installationID, limit)` to storage
2. Wire into dashboard handler
3. Layout: stat grid (4 cols) → recent scans table → developer override rates → by category table
4. Status pills, color-coded override rates, bordered table containers

**Done test:** Dashboard with recent scans, stats, and per-developer data.

---

## Task 5: Redesign landing page

**Files:** `internal/ui/templates/index.templ`

1. Hero: "Your AI writes code. TASS makes it accountable."
2. CTA: "Install the GitHub App →"
3. PR comment preview mockup
4. Three step cards: Install, Review, Decide
5. Tagline: "Machines state facts. Humans state intent."

**Done test:** Landing page polished for unauthenticated visitors.

---

## Task 6: Add Python AST rules for AI/ML libraries

**Files:** New in `rules/python/`

Create 4 rule pairs (.scm + .meta.yaml) following existing pattern:
1. `boto3` — detect `boto3.client()`, `boto3.resource()` → network_access
2. `strands_agent` — detect `Agent()` → external_api
3. `fastmcp` — detect `FastMCP()` → network_access
4. `opentelemetry` — detect `TracerProvider()`, `set_tracer_provider()` → network_access

**Done test:** `tass init` on the agentic-ai-workshop repo detects these.

---

## Task 7: Demo seed script

**Files:** New `cmd/tass/seed.go`, update `cmd/tass/main.go`

`tass seed --db tass.db` inserts:
- 1 installation, 3 repos, 8 scans (2 weeks), 25 decisions from alice/bob/carol
- Carol >50% revert rate
- Realistic capability names

**Done test:** `tass seed && tass serve` → populated dashboard.

---

## Task 8: Audit trail

**Files:** `internal/storage/storage.go`, new `internal/storage/migrations/004_manifest_history.sql`, new `internal/server/audit.go`, new `internal/ui/templates/audit.templ`, `internal/ui/handlers.go`, `internal/github/verifier.go`

1. Migration 004: `manifest_history` table (id, repo_id, commit_sha, content_yaml, committed_by, committed_at)
2. Storage: `SaveManifestSnapshot()`, `GetAuditTrail(ctx, repoID, from, to)`, `GetManifestHistory(ctx, repoID, limit)`
3. In verifier.go `commitManifest()`, call `SaveManifestSnapshot` after successful commit
4. API: `GET /api/audit?repo_id=...&from=...&to=...` → JSON timeline
5. API: `GET /api/audit/export?repo_id=...&format=csv` → CSV download
6. Template: `/audit/:repo_id` page with timeline (decisions + manifest commits), date filter via HTMX, "Export CSV" button
7. Dashboard: add "Audit" link in per-repo table
8. Use same design system (cards, pills, monospace for SHAs)

**Done test:** `/audit/1` shows timeline. CSV exports. Dashboard links work.

---

## Task 9: Cleanup and hardening

**Files:** `cmd/tass/main.go`, `Makefile`, `Dockerfile`, various

1. `tass version` with ldflags (version, commit SHA, build date) — update Makefile AND Dockerfile
2. `fatih/color` for CLI output in init + scan
3. Edge cases: no manifest → helpful msg, bad YAML → line number, no git → graceful fallback
4. `git rm -r --cached .history/`
5. Update README.md
6. `go test ./...` passes clean

**Done test:** `tass version` works. Colored CLI. Edge cases handled.

---

## Task 10: Deploy to Fly.io

**MANUAL — not for Cursor. Do this yourself.**

### Pre-deploy file changes (can ask Cursor for these):

1. Create `docker-entrypoint.sh` in repo root:
```bash
#!/bin/sh
echo "$TASS_GITHUB_PRIVATE_KEY" > /app/private-key.pem
chmod 600 /app/private-key.pem
exec tass serve --addr :8080 --db /data/tass.db
```

2. Update Dockerfile — add before CMD:
```dockerfile
COPY --from=builder /app/docker-entrypoint.sh /app/docker-entrypoint.sh
```
Replace CMD with:
```dockerfile
CMD ["/bin/sh", "/app/docker-entrypoint.sh"]
```

3. Update fly.toml env:
```toml
[env]
  TASS_GITHUB_PRIVATE_KEY_PATH = "/app/private-key.pem"
  TASS_BASE_URL = "https://tass-security.fly.dev"
```

### Deploy commands:
```bash
fly launch --copy-config --name tass-security --region iad
fly volumes create tass_data --region iad --size 1
fly secrets set \
  TASS_GITHUB_APP_ID="..." \
  TASS_GITHUB_CLIENT_ID="..." \
  TASS_GITHUB_CLIENT_SECRET="..." \
  TASS_GITHUB_WEBHOOK_SECRET="..." \
  TASS_SESSION_SECRET="$(openssl rand -hex 32)"
fly secrets set TASS_GITHUB_PRIVATE_KEY="$(cat your-app.pem)"
fly deploy
```

### Post-deploy:
- Update GitHub App webhook URL → `https://tass-security.fly.dev/webhooks/github`
- Update OAuth callback → `https://tass-security.fly.dev/auth/github/callback`
- Install app on demo repo → setup PR auto-opens
- Seed: `fly ssh console` → `tass seed --db /data/tass.db`

---

# WORKFLOW

Say "do task N" → Cursor implements → `go build && go test` → commit → next task.

**Thursday priority:** 1-7 must-have. 8-9 should-have. 10 is go-live.

*— Team Blue Hearts 💙*