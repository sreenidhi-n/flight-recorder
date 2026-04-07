# TASS — Trusted AI Security Scanner

> *Machines state facts. Humans state intent.*

TASS is a GitHub App that automatically scans every pull request for newly introduced capabilities in AI-generated code — new dependencies, HTTP calls, database writes, filesystem access — and surfaces them for explicit human review before merge.

**Nobody installs a binary. Nobody opens a terminal. The GitHub App IS the product.**

---

## How it works

```
Developer opens PR
  → TASS scans changed files (Layer 0: deps + Layer 1: AST)
  → Diffs against tass.manifest.yaml
  → Posts PR comment listing novel capabilities
  → Creates GitHub Check (status: action_required)

Developer clicks the link in the comment
  → Lands on TASS verification UI
  → Clicks Confirm or Revert for each capability
  → TASS commits updated manifest to PR branch
  → GitHub Check goes green ✓
```

---

## Stack

| Layer | Technology |
|---|---|
| Language | Go (single binary) |
| UI | Templ + HTMX, zero JS framework |
| CSS | Custom design system, dark mode via `prefers-color-scheme` |
| Database | SQLite via `modernc.org/sqlite` (pure Go, CGO-free) |
| AST scanning | Tree-sitter via `smacker/go-tree-sitter` (CGO) |
| GitHub | GitHub App: JWT auth, webhooks, Checks API, Contents API |
| Deploy | Fly.io (single binary, persistent volume for SQLite) |

---

## CLI

```bash
tass init                    # Scan repo, generate tass.manifest.yaml baseline
tass scan [--base main]      # Diff HEAD against base branch, report novel caps
tass serve                   # Start the web server (see env vars below)
tass seed [--db tass.db]     # Insert demo data for dashboard preview
tass version                 # Print version, commit SHA, build date
```

### Environment variables (server)

| Variable | Required | Description |
|---|---|---|
| `TASS_GITHUB_APP_ID` | ✓ | GitHub App numeric ID |
| `TASS_GITHUB_CLIENT_ID` | ✓ | OAuth client ID |
| `TASS_GITHUB_CLIENT_SECRET` | ✓ | OAuth client secret |
| `TASS_GITHUB_WEBHOOK_SECRET` | ✓ | Webhook HMAC secret |
| `TASS_GITHUB_PRIVATE_KEY_PATH` | ✓ | Path to RSA private key `.pem` |
| `TASS_SESSION_SECRET` | ✓ | 32+ byte random string for cookie signing |
| `TASS_BASE_URL` | ✓ | Public URL, e.g. `https://tass.example.com` |

---

## Local development

```bash
# Prerequisites: Go 1.22+, CGO_ENABLED=1, Xcode CLT (macOS)

git clone https://github.com/tass-security/tass
cd tass

# Build
make build          # → ./tass

# Run tests
make test

# Regenerate templates after editing .templ files
make generate

# Demo: seed a local DB and start the server
./tass seed --db demo.db
source .env.local   # set env vars (see above)
./tass serve --db demo.db
# → http://localhost:8080/dashboard?installation_id=12345
```

---

## Detection layers

**Layer 0 — Dependency file diffing**
Compares `go.mod`, `requirements.txt`, `package.json`, etc. between the PR head and base. Every newly added package is a detected capability.

**Layer 1 — AST scanning (Tree-sitter)**
Structural queries (`.scm` files in `rules/`) detect API calls, database operations, filesystem access, and privilege patterns directly in source code. Supports Go, Python, JavaScript.

Current rules cover: `net/http`, `database/sql`, `os` (filesystem), `exec.Command`, `boto3`, `strands.Agent`, `FastMCP`, OpenTelemetry, and more.

---

## Deployment (Fly.io)

```bash
fly launch --name tass-yourname --region iad
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

See [CLAUDE.md](CLAUDE.md) for the full implementation roadmap.

---

## License

MIT
