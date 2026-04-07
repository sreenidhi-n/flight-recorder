# TASS v3.0 — The Disagreement Engine

## What This Project Is

TASS (Trusted AI Security Scanner) is a **hosted SaaS** delivered as a **GitHub App** that automatically scans pull requests for newly introduced capabilities in AI-generated code. It compares detected capabilities against a declarative manifest (`tass.manifest.yaml`) committed to the repository, and surfaces novel/unexpected capabilities for developer verification via a hosted web UI.

The core interaction: developer opens a PR → TASS posts a PR comment listing new capabilities → developer clicks a link → lands on hosted verification UI → clicks Confirm or Revert → TASS commits the updated manifest to the PR branch → GitHub Check goes green.

**Nobody installs a binary. Nobody opens a terminal. The GitHub App IS the product.**

## Architecture

Single Go binary deployed to Fly.io. Contains:
- **Scanner Engine** — Layer 0 (dependency file diffing) + Layer 1 (Tree-sitter AST queries)
- **GitHub Integration** — App JWT auth, webhook handler, Checks API, PR comments, file fetching via GitHub API
- **Web App** — Templ (type-safe Go templates) + HTMX + Pico CSS for the verification UI and dashboard
- **Storage** — SQLite via `modernc.org/sqlite` (pure Go), multi-tenant (scoped by GitHub installation + repo)
- **Auth** — GitHub OAuth for developer authentication on the web UI

## Tech Stack Rules (STRICT)

- **Language:** Go only. No Python, no JavaScript, no TypeScript.
- **Templates:** Templ (`github.com/a-h/templ`) — NOT `html/template`.
- **CSS:** Pico CSS via CDN. No Tailwind, no custom CSS framework. Minimal custom CSS overrides only.
- **Interactivity:** HTMX via CDN. No React, no Vue, no frontend JS frameworks.
- **Database:** SQLite via `modernc.org/sqlite` (pure Go, CGO-free for storage).
- **Tree-sitter:** `github.com/smacker/go-tree-sitter` with CGO. Grammars for Go, Python, JavaScript.
- **YAML:** `gopkg.in/yaml.v3` (pure Go).
- **HTTP Router:** Chi (`github.com/go-chi/chi/v5`) or stdlib `net/http`.
- **JWT:** `github.com/golang-jwt/jwt/v5` (pure Go).
- **Testing:** stdlib `testing` package. No testify unless absolutely necessary.

## Code Conventions

- Use `internal/` for all packages that are not meant to be imported externally.
- Use `pkg/` only for packages meant to be importable by external tools (manifest, contracts).
- All scanner interfaces must accept `[]byte` (not just file paths) so they work for both local files AND files fetched via GitHub API.
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)`. No bare `return err`.
- Logging: use `log/slog` (stdlib structured logging).
- Naming: follow Go conventions. No stuttering (`scanner.Scanner` is fine, `scanner.ScannerService` is not).

## Package Structure

```
cmd/tass/           → CLI entrypoint (serve, init, scan, version)
internal/scanner/   → Detection engine (dep parsing, AST queries)
internal/github/    → GitHub App (JWT, webhooks, checks, comments, file fetch)
internal/auth/      → OAuth, sessions, middleware
internal/ui/        → Templ templates + HTMX handlers
internal/storage/   → SQLite storage layer
internal/server/    → HTTP server, routing, health
pkg/manifest/       → Manifest YAML read/write/diff
pkg/contracts/      → Shared types (Capability, CapabilitySet, VerificationReceipt)
rules/              → Tree-sitter .scm query files (data, not code)
```

## Key Data Types (pkg/contracts/)

- `Capability` — a single detected capability (ID, Name, Category, Source, Location, Confidence, RawEvidence)
- `CapabilitySet` — output of a scan (list of capabilities + metadata)
- `VerificationReceipt` — a developer's confirm/revert decision
- `CapCategory` — enum: external_dependency, external_api, database_operation, network_access, filesystem_operation, privilege_pattern
- `DetectionLayer` — enum: layer0_dependency, layer1_ast

## Critical Design Decisions

1. **Capability IDs must be deterministic and stable.** Derived from (category + source_identifier + canonical_name). NEVER from line numbers, file offsets, or anything volatile.
2. **Manifest diffing is a set difference on IDs.** A capability is either in the manifest or it isn't.
3. **Scanner interfaces are bytes-first.** `ParseBytes(content []byte)` and `ScanBytes(content []byte, ...)` are primary. File-path versions are convenience wrappers.
4. **Detection rules are data, not code.** Tree-sitter queries live in `rules/` as `.scm` files with `.meta.yaml` sidecars.
5. **Never write customer source code to disk or database.** Process in-memory only. Store only structured CapabilitySet output.

## Build & Test Commands

```bash
go build ./cmd/tass          # Build binary
go test ./...                # Run all tests
templ generate               # Generate Go code from .templ files
templ generate --watch       # Watch mode for UI development
```

## Development Environment

- macOS, Apple Silicon (M4 Pro)
- Go 1.22+
- CGO_ENABLED=1 (required for Tree-sitter)
- Xcode Command Line Tools installed

## Roadmap Reference

The full implementation roadmap is in `TASS_v3_Implementation_Roadmap.md` in this directory. It contains 29 steps across 4 phases. Follow it sequentially — each step has a "Done test" that must pass before moving on.