# TASS — Architecture Specification

**Version:** 0.1 · **Spec ref:** capability-manifest-spec@0.1 · **Status:** Active

---

## 1. System Boundary

TASS is a single statically-linked Go binary (`cmd/tass`) deployed as a Fly.io process. It is simultaneously a CLI tool and a production HTTP server. No sidecar processes, no message queues, no external caches. Every subsystem runs in-process.

```
┌────────────────────────────────────────────────────────────────┐
│  tass (single binary, pid 1 in container)                      │
│                                                                 │
│  CLI mode:  tass init | scan | seed | policy | verify-runtime  │
│  Server mode: tass serve ──► :8080                             │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  internal/   │  │  internal/   │  │  internal/           │  │
│  │  scanner/    │  │  github/     │  │  server/ + ui/       │  │
│  │  (CGO)       │  │  (HTTP)      │  │  (Templ + HTMX)      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └─────────────────┴──────────────────────┘             │
│                           │                                     │
│                  internal/storage/ (SQLite WAL)                 │
└────────────────────────────────────────────────────────────────┘
```

**Constraints that must not be violated:**

| Constraint | Rationale |
|---|---|
| `CGO_ENABLED=1` at build time | `github.com/smacker/go-tree-sitter` wraps C grammars |
| `modernc.org/sqlite` (pure Go) | Prevents a second CGO linker dependency for storage |
| No external font or asset files at runtime | PDF output uses standard Type1 core fonts; rules embedded via `//go:embed` |
| Single SQLite file at `/data/tass.db` | WAL mode; no concurrent writer processes allowed |
| No goroutine-level parser parallelism | `ASTScanner` wraps a single Tree-sitter parser behind a `sync.Mutex` |
| All secrets via environment variables only | Private key written to disk only by `docker-entrypoint.sh` at boot |

---

## 2. Package Dependency Graph

Allowed import directions (no cycles permitted):

```
cmd/tass
  → internal/{github,server,ui,scanner,auth,audit,compliance,policy,contract,runtime}
  → pkg/{contracts,manifest}

internal/github   → internal/{scanner,storage,audit}  → pkg/{contracts,manifest}
internal/server   → internal/{storage,audit,compliance,github,auth}
internal/ui       → internal/storage
internal/scanner  → pkg/{contracts,manifest}
internal/audit    → internal/storage          (via adapter: internal/server/audit_adapter.go)
internal/compliance → internal/{audit,storage}
internal/runtime  → pkg/manifest, internal/runtime/parsers
internal/contract → pkg/contracts

pkg/*             → (no internal/ imports — shared types only)
```

**Circular import prevention:** `internal/audit` and `internal/storage` use mirrored struct types (`audit.AuditEvent` / `storage.AuditEvent`). The bridge lives exclusively in `internal/server/audit_adapter.go`. Adding a direct import in either direction breaks this invariant.

---

## 3. Capability Mapping Engine

### 3.1 Detection Layers

The engine has two strictly ordered layers. Layer 0 always runs first; Layer 1 runs concurrently across files after Layer 0 completes.

```
Layer 0 — Dependency Diffing
  Input:  go.mod, requirements.txt, package.json (base branch vs HEAD)
  Output: []Capability{Category: external_dependency, Source: layer0_dependency}
  ID:     dep:{go|py|npm}:{package_path}
  Note:   // indirect requires in go.mod are silently skipped (known gap)

Layer 1 — Tree-sitter AST Queries
  Input:  changed source files (.go, .py, .js) at HEAD
  Output: []Capability{Category: <from meta.yaml>, Source: layer1_ast}
  ID:     ast:{lang}:{cap_id}:{symbol_capture_text}
  Note:   Entire file is AST-scanned, not just changed lines. manifest.Diff
          filters by ID — pre-existing unmanifested caps in a touched file
          will appear as novel.
```

### 3.2 Rule Loading Precedence

```
1. --rules-dir flag (explicit override, dev/testing)
2. ./rules/ on disk (present → used; dev environment)
3. Embedded FS (embedrules.go //go:embed rules → production default)
```

Rule invalidation at load time — a rule is **dropped** if any of the following are true:
- `.meta.yaml` missing or unreadable
- `confidence` is `0` or missing
- `cap_id` is empty
- `symbol_capture` is empty
- `.scm` query fails `sitter.NewQuery` compilation

### 3.3 Capability Category Boundaries

| Category constant | YAML string | Assigned by | Badge |
|---|---|---|---|
| `CatExternalDep` | `external_dependency` | Layer 0 parsers (hardcoded) | purple |
| `CatNetworkAccess` | `network_access` | `.meta.yaml` | blue |
| `CatExternalAPI` | `external_api` | `.meta.yaml` | blue |
| `CatDatabaseOp` | `database_operation` | `.meta.yaml` | orange |
| `CatFileSystem` | `filesystem_operation` | `.meta.yaml` | green |
| `CatPrivilege` | `privilege_pattern` | `.meta.yaml` | red |

Categories are assigned at detection time and **never mutated** by downstream systems (storage, UI, contract engine, compliance reporter). Any code that changes `Category` after `ScanDiff` returns is a bug.

### 3.4 Manifest Diff Contract

`manifest.Diff(detected CapabilitySet, existing *Manifest) []Capability`

- Performs pure set difference on `Capability.ID` (deterministic string key).
- No fuzzy matching, no location comparison, no evidence comparison.
- A capability whose ID appears in the manifest at any status (`confirmed`, `reverted`, `auto_detected`) is **not** novel.
- The returned slice contains only novel capabilities. Callers must not sort or deduplicate the output; `manifest.Diff` guarantees stable iteration order.

### 3.5 Contract Check Boundaries

`contract.Check(novel []Capability) []Violation`

Evaluated on the **novel** slice only, in this exact order:

1. `forbidden` — category key exists in `Contract.Forbidden`; pattern matches via glob or token substring.
2. `not_in_allowed` — category key exists in `Contract.Allowed`; no pattern in the allow list matches.
3. `limit_exceeded` — novel count per category exceeds `Contract.Limits[category]`.

Rules 1 and 2 are evaluated per capability. Rule 3 is evaluated after all per-capability checks.

CLI exit codes: `0` = clean · `1` = novel capabilities (needs review) · `2` = contract violation (hard block).

The server-side pipeline (`internal/github/pipeline.go`) fetches `tass.contract.yaml` from the **base branch** via Contents API, not the PR head, to prevent contract bypass via PR.

---

## 4. Runtime Verification Engine

Separate from the AST scan pipeline. Used offline via `tass verify-runtime` or via `POST /api/runtime-verify`.

```
Input:  VPC Flow Log file (AWS v2 format, ACCEPT records, TCP/UDP, public IPs)
        tass.manifest.yaml

Pipeline:
  parsers.ParseVPCFlow() → []Record
  → time filter (--since)
  → dedupe by dstIP:dstPort → map[key]*ObservedEndpoint
  → parallel reverse DNS (one goroutine per unique IP — no worker pool)
  → ExtractNetworkEndpoints(manifest) → []ManifestEndpoint
      (only network_access + external_api categories)
      (extracts from Name + Note fields via hostnameRe — NOT from Locations or RawEvidence)
  → MatchesManifest(hostname, patterns): exact → glob (path.Match) → subdomain suffix
  → DiffReport{ObservedInManifest, ObservedNotInManifest, ManifestNeverObserved}

Exit: 0 = no drift · 1 = drift detected
```

**Boundary:** `ExtractNetworkEndpoints` reads only `entry.Name` and `entry.Note`. Endpoints encoded only in `Locations[].File` or original `RawEvidence` are invisible to runtime matching. This is a documented gap.

---

## 5. Audit and Hash Chain

`internal/audit/log.go` — append-only event emission via `Emitter.Emit(ctx, action, targetID, before, after)`.

Hash formula (per tenant, sequential):
```
hash[n] = SHA-256( prev_hash[n-1] || canonical_json(event[n] without hash fields) )
```

`internal/audit/chain.go` — `VerifyChain(rows []ChainRow) VerifyResult` recomputes the full per-tenant chain and returns the first broken event ID. Breaking the chain is surface-visible:
- CLI `tass compliance`: exits with code `2`
- HTTP compliance endpoint: returns `HTTP 207` with `X-TASS-Chain-Integrity: broken`

**Data minimisation boundary:** `before_json` and `after_json` store capability metadata (IDs, names, categories, decisions) only. Source code snippets and `RawEvidence` content are never written to the audit table.

---

## 6. RBAC Enforcement Points

Role order: `Viewer(1) < Developer(2) < Approver(3) < Admin(4)`.

| Endpoint | Minimum role | Enforcement mechanism |
|---|---|---|
| `POST /api/verify` | `Developer` | `EnforceInHandler()` in handler |
| `POST /ui/verify` | `Developer` | `EnforceInHandler()` in handler |
| `GET /compliance/:repo` | `Admin` | `RequireRoleMiddleware` at route level |
| Slash command `/approve`, `/reject` | `Developer` | `SlashCommandHandler` pre-check |

`PermCache.Resolve()` hits GitHub Collaborators API; results are cached for 5 minutes keyed by `(login, "owner/repo")`. Failures are **closed**: any API error maps to `Viewer`.

Every `permission_denied` audit event must be emitted by the caller, not the RBAC library. `EnforceInHandler` does not emit; callers are responsible (NIST AC-6(9)).

---

## 7. HTTP Server Routing Constraints

`internal/server/server.go` owns the canonical route table. No other file registers routes.

Rate limiting: IP-based, 60 req/min sliding window. Applied to all `/api/*` and `/ui/*` routes. Static assets (`/static/`) are exempt. The `/health` endpoint is exempt.

Webhook HMAC verification (`internal/github/webhook.go`) executes before the request body is read by any handler. A signature failure returns `HTTP 401` immediately; the body is never deserialized.

---

## 8. Standard Anti-Patterns

The following patterns have been observed in the codebase and must not be propagated:

### AP-1: Layer 1 whole-file re-scan on diff
**Location:** `internal/scanner/scanner.go` — `ScanDiff`, `ScanRemote`  
**Problem:** When a file appears in `git diff --name-only`, TASS runs all AST rules against the entire file at HEAD. Pre-existing, unmanifested capabilities in the same file will surface as novel even if they were not introduced by the PR. `manifest.Diff` is the only filter — no base-branch AST comparison is performed.  
**Correct pattern:** Before classifying a match as novel, compare its ID against both the committed manifest and against an AST scan of the base-branch version of the same file.

### AP-2: Unbounded goroutine fan-out in DNS resolution
**Location:** `internal/runtime/diff.go` lines 106–114  
**Problem:** One goroutine is spawned per unique `dstIP:dstPort` entry with no worker pool. For large VPC flow logs (>10,000 unique IPs) this creates a goroutine storm.  
**Correct pattern:** Use a bounded worker pool (`semaphore` or `errgroup` with `SetLimit`).

### AP-3: `gitShowFile` error conflation
**Location:** `internal/scanner/scanner.go` (Layer 0 dep diff)  
**Problem:** `gitShowFile` returns `nil, nil` on any failure — file-not-found, git error, and permission errors are all treated identically. A missing base-branch dep file inflates the "added" dependency count.  
**Correct pattern:** Distinguish `object not found` (file did not exist in base — all deps are genuinely new) from other errors (operational failure — propagate).

### AP-4: `// indirect` requires invisible to Layer 0
**Location:** `internal/scanner/gomod.go` — `GoModParser`  
**Problem:** `// indirect` requires are skipped. Transitive dependency additions are not reported. A PR that introduces a new transitive dep with a privileged capability (e.g., a network-calling package pulled in by a direct dep) will not generate a novel capability entry.  
**Correct pattern:** Parse indirect requires; emit them with `Confidence: 0.70` and a `Note: "indirect dependency"` to distinguish from direct.

### AP-5: Runtime hostname extraction ignores `Locations` and `RawEvidence`
**Location:** `internal/runtime/manifest.go` — `hostnamesFromEntry`  
**Problem:** `ExtractNetworkEndpoints` reads only `entry.Name` and `entry.Note`. An endpoint URL encoded only in the original scan evidence (e.g., `http.Get("https://internal.corp.example.com/...")`) will not appear in `ManifestEndpoint` patterns and will always be classified as drift.  
**Correct pattern:** Also scan `entry.Locations`-adjacent evidence stored in the manifest, or add an explicit `endpoints: []` field to `ManifestEntry`.

### AP-6: Parser mutex as a global serialization point
**Location:** `internal/scanner/ast.go` — `ASTScanner`  
**Problem:** A single `sync.Mutex` wraps the tree-sitter parser. All files in `ScanRepo` are scanned sequentially even when run from `tass init` with no concurrency constraint. On repos with hundreds of source files this is a latency bottleneck.  
**Correct pattern:** Instantiate one parser per worker goroutine (each grammar is reentrant if used from a single goroutine); fan-out with a bounded worker pool.

### AP-7: Duplicate redundant COPY in production Dockerfile
**Location:** `Dockerfile` — runtime stage  
**Problem:** `COPY rules /app/rules` copies the rules directory into the runtime image, but `buildASTScanner` selects the embedded FS (not the disk path) whenever `./rules` does not exist relative to the working directory at runtime. The `COPY` adds image layer weight and misleads operators into thinking rules can be hot-swapped.  
**Correct pattern:** Remove the `COPY rules` line from the runtime stage; document that rule updates require a binary rebuild.

### AP-8: Contract bypass via head-branch contract file
**Location:** `internal/github/pipeline.go`  
**Pattern already correctly handled** — `tass.contract.yaml` is fetched from the base branch. This note exists to prevent regression: any refactor that changes the fetch ref to `PR.Head.SHA` breaks the security invariant.

---

## 9. Build and Embed Invariants

| Artifact | How embedded | Must rebuild if changed |
|---|---|---|
| Tree-sitter rules (`rules/`) | `embedrules.go` `//go:embed rules` | Yes — `go build` |
| JSON schemas (`cmd/tass/schemas/`) | `cmd/tass/spec.go` `//go:embed schemas` | Yes — `go build` |
| Templ templates | `templ generate` → `*_templ.go` | Yes — `make generate && go build` |

Correct build order: `make generate → go build ./cmd/tass → go test ./...`

`version`, `commit`, `buildDate` are set via `-ldflags` in the Makefile. A binary built without ldflags reports `dev / none / unknown` — acceptable for local development, not for production deploys.

---

## 10. Spec Compliance Reference

| Command | Spec behaviour |
|---|---|
| `tass spec --version` | Prints `0.1` (hardcoded in `cmd/tass/spec.go`) |
| `tass validate-manifest <path>` | YAML → JSON normalize → `cmd/tass/schemas/manifest.schema.json` |
| `tass validate-manifest <path> --contract` | Same with `schemas/contract.schema.json` |

Schema files are the reference implementation of `https://github.com/sreenidhi-n/capability-manifest-spec`. Do not edit them directly in this repo; pull from the spec repo and re-embed.
