# TASS — Trusted AI Security Scanner

> **Automatic capability detection for AI-generated code. Zero install. GitHub App is the product.**

TASS scans every pull request for newly introduced capabilities — new dependencies, HTTP calls, database writes, filesystem operations — and surfaces them for developer review before merge.

```
Developer opens PR → TASS scans → posts PR comment → dev clicks link →
reviews capabilities in browser → clicks Confirm/Revert →
TASS commits updated manifest → check goes green
```

Nobody installs a binary. Nobody opens a terminal. **The GitHub App is the product.**

---

## What TASS Detects

| Category | Examples |
|----------|---------|
| 📦 New Dependency | `requests==2.31.0` in requirements.txt, `stripe-go v76` in go.mod |
| 🌐 External API / Network | `http.Get(...)`, `fetch(...)`, `requests.post(...)` |
| 🗄️ Database Operation | `sql.Open(...)`, `sqlite3.connect(...)` |
| 📁 Filesystem Access | `os.WriteFile(...)`, `open("w")`, `fs.writeFile(...)` |
| 🔐 Privilege Pattern | sudo calls, capability escalation patterns |

Detection runs on **two layers**:
- **Layer 0 — Dependency diff:** Compares `go.mod`, `requirements.txt`, `package.json` between base and head branches.
- **Layer 1 — AST queries:** Tree-sitter queries on Go, Python, JavaScript source files.

---

## Architecture

Single Go binary deployed on [Fly.io](https://fly.io). No microservices. No Kubernetes.

```
GitHub Webhooks → Webhook Handler → Scanner Engine → SQLite Store
                                                  ↓
                  PR Comment ← Checks API ← Verification Decision Engine
                                                  ↓
                  Developer Browser → Templ+HTMX Verification UI
```

**Stack:** Go · Templ + HTMX · Pico CSS · SQLite · Tree-sitter · GitHub App

---

## Quick Start (Install the GitHub App)

1. Go to `https://github.com/apps/tass-security` (or your self-hosted URL)
2. Click **Install** → select repositories → authorize
3. TASS opens a setup PR on each repo with the initial `tass.manifest.yaml`
4. Merge the setup PR to activate scanning

That's it. Every future PR is scanned automatically.

---

## Self-Hosting

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full Fly.io deployment guide.

```bash
# Quick deploy
fly launch --copy-config
fly secrets set TASS_GITHUB_APP_ID=... TASS_GITHUB_WEBHOOK_SECRET=... # etc
fly deploy
```

---

## The Manifest

`tass.manifest.yaml` is committed to your repository. It's a behavioral SBOM — a declarative record of what your code can do. TASS reads it to know what's already approved; any new capability not in the manifest triggers a verification request.

```yaml
# tass.manifest.yaml — auto-generated and maintained by TASS
schema_version: "1"
generated_at: "2026-03-22T10:00:00Z"
repo: acme-corp/payments-service

capabilities:
  - id: "dep:python:requests"
    name: "requests"
    category: external_dependency
    confirmed: true
    confirmed_by: "alice@acme.com"
    confirmed_at: "2026-03-22T10:05:00Z"
    justification: "HTTP client for payment gateway integration"
```

---

## Development

```bash
go build ./cmd/tass           # Build binary
go test ./...                 # Run all tests
templ generate                # Regenerate UI templates
tass serve --addr :8080       # Start server (requires env vars)
```

**Required env vars for `tass serve`:**

| Variable | Description |
|----------|-------------|
| `TASS_GITHUB_APP_ID` | GitHub App ID |
| `TASS_GITHUB_CLIENT_ID` | OAuth App Client ID |
| `TASS_GITHUB_CLIENT_SECRET` | OAuth App Client Secret |
| `TASS_GITHUB_WEBHOOK_SECRET` | Webhook HMAC secret |
| `TASS_GITHUB_PRIVATE_KEY_PATH` | Path to `.pem` private key |
| `TASS_SESSION_SECRET` | 32+ random bytes for cookie signing |
| `TASS_BASE_URL` | Public URL (e.g. `https://app.tass.dev`) |

---

## Project Structure

```
cmd/tass/           CLI entrypoint (serve, init, scan, version)
internal/auth/      GitHub OAuth + signed cookie sessions
internal/github/    GitHub App: JWT, webhooks, Checks API, comments, file fetch
internal/scanner/   Detection engine (Layer 0 dep diff + Layer 1 AST)
internal/server/    HTTP server, routing, rate limiting, logging
internal/storage/   SQLite multi-tenant storage
internal/ui/        Templ+HTMX web UI handlers and templates
pkg/contracts/      Shared types (Capability, CapabilitySet, decisions)
pkg/manifest/       Manifest YAML read/write/diff
rules/              Tree-sitter .scm query files (data, not code)
```

---

## License

MIT. See [LICENSE](LICENSE).

---

*TASS v3.0 — "The Disagreement Engine"*
