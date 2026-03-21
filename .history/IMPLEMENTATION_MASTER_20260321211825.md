# TASS v3.0 — "The Disagreement Engine"
## Step-by-Step Implementation Roadmap

> **Architect:** Team Blue Hearts (Principal Architect)
> **Developer:** S (Solo Founder)
> **Stack:** Go. Literally. Just that.
> **Machine:** MacBook M4 Pro (Apple Silicon)
> **Philosophy:** Walking Skeleton → Flesh on Bones → Muscles → Skin
> **Product Model:** Hosted SaaS via GitHub App. Not a CLI tool with a web UI bolted on.

---

## Roadmap Overview

| Phase | Name | Sessions | Cumulative Outcome |
|-------|------|----------|--------------------|
| 1 | **The Skeleton** | 6 steps (~16 hrs) | Go monorepo + manifest schema + core types compiling. `tass init` generates a manifest from a real repo. |
| 2 | **The Nervous System** | 7 steps (~20 hrs) | Full scanner pipeline: Layer 0 (dep diffing) + Layer 1 (Tree-sitter AST) producing a `CapabilitySet`. Manifest diffing identifies novel capabilities. |
| 3 | **The Platform** | 8 steps (~26 hrs) | GitHub App + webhook handler + OAuth + hosted scan pipeline + decision engine. PR opened → webhook fires → TASS scans → PR comment + Check posted. All hosted. |
| 4 | **The Experience** | 8 steps (~28 hrs) | Hosted verification UI + dashboard + PR integration polish + Fly.io deployment. Full end-to-end: dev opens PR → TASS comments in seconds → dev clicks link → verifies in browser → TASS commits updated manifest → check goes green. **Nobody installs anything.** |

**Total: 29 steps, ~90 hours, ~6-7 weeks at ~3 sessions/day**

---

## Phase 1: The Skeleton
### *"Make the compiler happy, make the types real, make `tass init` work."*

The goal of Phase 1 is deceptively simple: by the end, you should be able to run `tass init` on a real Go repository and get a `tass.manifest.yaml` file that looks correct. No scanning intelligence yet — just the bones.

---

### Step 1.1 — Go Monorepo Scaffolding
**⏱ ~2 hours** | **Dependencies: None**

Set up the Go module with the package structure from the design doc. This is the foundation everything builds on.

**Deliverables:**
- `go mod init github.com/tass-security/tass`
- Directory structure:
  ```
  cmd/tass/           → main.go (entrypoint: `tass serve` for production, `tass init`/`tass scan` for local dev)
  internal/scanner/   → Scanner package (detection engine — works on both local files AND in-memory bytes)
  internal/github/    → GitHub App: JWT auth, webhooks, Checks API, PR comments, file fetching
  internal/auth/      → OAuth flow, session management, middleware
  internal/ui/        → UI package (Templ + HTMX handlers)
  internal/storage/   → SQLite storage layer (multi-tenant)
  internal/server/    → HTTP server, routing, health checks
  pkg/manifest/       → Manifest read/write/diff (public API — importable by external tools)
  pkg/contracts/      → Shared types (CapabilitySet, VerificationReceipt, etc.)
  rules/              → Tree-sitter .scm query files (data, not code)
  ```
- Minimal `main.go` with a stub CLI using `cobra` or just `os.Args` (keep it dead simple — cobra can come later)
- `go build ./cmd/tass` compiles and produces a binary

**The "Done" test:** `./tass --version` prints `tass v3.0.0-dev`.

**Notes:**
- Do NOT reach for cobra/viper yet unless you already have muscle memory. A `switch os.Args[1]` is fine for now. You're going to refactor this 4 times anyway.
- Keep `pkg/` for things that external consumers (future SDK, manifest tooling) might import. Keep `internal/` for everything else.
- The `internal/github/` and `internal/auth/` packages are empty stubs for now — just create the directories. They get built in Phase 3.

---

### Step 1.2 — Core Data Contracts
**⏱ ~2 hours** | **Dependencies: Step 1.1**

Define the Go structs that are the shared language of the entire system. This is the most important step in Phase 1 — get these wrong and everything downstream hurts.

**Deliverables in `pkg/contracts/`:**
```go
// Capability — a single detected capability
type Capability struct {
    ID          string          `json:"id" yaml:"id"`
    Name        string          `json:"name" yaml:"name"`
    Category    CapCategory     `json:"category" yaml:"category"`
    Source      DetectionLayer  `json:"source" yaml:"source"`
    Location    CodeLocation    `json:"location" yaml:"location"`
    Confidence  float64         `json:"confidence" yaml:"confidence"`
    RawEvidence string          `json:"raw_evidence" yaml:"raw_evidence"`
}

// CapCategory enum
type CapCategory string
const (
    CatExternalDep   CapCategory = "external_dependency"
    CatExternalAPI   CapCategory = "external_api"
    CatDatabaseOp    CapCategory = "database_operation"
    CatNetworkAccess CapCategory = "network_access"
    CatFileSystem    CapCategory = "filesystem_operation"
    CatPrivilege     CapCategory = "privilege_pattern"
)

// DetectionLayer enum
type DetectionLayer string
const (
    LayerDependency DetectionLayer = "layer0_dependency"
    LayerAST        DetectionLayer = "layer1_ast"
)

// CapabilitySet — output of a scan
type CapabilitySet struct {
    RepoRoot     string       `json:"repo_root"`
    ScanTime     time.Time    `json:"scan_time"`
    CommitSHA    string       `json:"commit_sha,omitempty"`
    Capabilities []Capability `json:"capabilities"`
}

// VerificationReceipt — a developer's decision
type VerificationReceipt struct {
    CapabilityID  string            `json:"capability_id"`
    Decision      VerificationDecision `json:"decision"`
    Justification string            `json:"justification,omitempty"`
    DecidedBy     string            `json:"decided_by"`
    DecidedAt     time.Time         `json:"decided_at"`
}

type VerificationDecision string
const (
    DecisionConfirm VerificationDecision = "confirm"
    DecisionRevert  VerificationDecision = "revert"
)
```

**The "Done" test:** All structs compile. Write a trivial `contracts_test.go` that creates one of each and marshals to JSON/YAML. Green tests.

**Blindspot warning:** Resist the urge to over-design these. You WILL iterate on them. The goal is "correct enough to build on" not "final schema." The compiler will yell at you everywhere when you change a field — that's the whole point of the single-binary architecture.

---

### Step 1.3 — Manifest Schema Design & YAML Serialization
**⏱ ~3 hours** | **Dependencies: Step 1.2**

This is the **load-bearing architectural decision** (the doc says so, and I agree). Design the `tass.manifest.yaml` format and build read/write/validate.

**Deliverables in `pkg/manifest/`:**
```yaml
# tass.manifest.yaml — target format
version: "1"
generated_at: "2026-02-20T10:00:00Z"
repo: "github.com/example/myapp"

capabilities:
  - id: "dep:go:github.com/stripe/stripe-go/v76"
    name: "stripe-go"
    category: external_dependency
    source: layer0_dependency
    confirmed_by: "developer@example.com"
    confirmed_at: "2026-02-20T10:05:00Z"
    note: "Payment processing for checkout flow"

  - id: "ast:go:net/http:Client.Do"
    name: "HTTP client outbound request"
    category: network_access
    source: layer1_ast
    first_detected: "2026-02-20T10:00:00Z"
    locations:
      - file: "internal/client/api.go"
        line: 42
```

**Implementation:**
- `manifest.go` — `type Manifest struct` with YAML tags
- `manifest.go` — `Load(path string) (*Manifest, error)` — reads and validates
- `manifest.go` — `Save(m *Manifest, path string) error` — writes with header comments
- `manifest.go` — `Diff(detected CapabilitySet, existing Manifest) []Capability` — returns **novel** capabilities (the core mechanic!)
- Use `gopkg.in/yaml.v3` (pure Go, no CGO)

**The "Done" test:** Round-trip test: create a Manifest → save to YAML → load from YAML → deep equal. Diff test: manifest with 3 capabilities, CapabilitySet with 5 → Diff returns 2.

**Critical dependency identified:** The `Diff` function's matching logic is the heart of the system. You need to decide: does matching happen on `ID` alone? On `Name + Category`? Think about this NOW. I recommend: match on `ID`, which should be a deterministic hash of (category + source_identifier + name). This makes the diff a simple set difference.

---

### Step 1.4 — Layer 0 Dependency Parser (go.mod only)
**⏱ ~3 hours** | **Dependencies: Step 1.2**

Build the first real scanner: parse `go.mod` and extract dependencies as capabilities. Start with go.mod ONLY. One language. Get it perfect.

**Deliverables in `internal/scanner/`:**
- `depparser.go` — interface:
  ```go
  type DepParser interface {
      // ParseBytes parses dependency file content from raw bytes.
      // This is the primary interface — works for both local files
      // AND files fetched via GitHub API in Phase 3.
      ParseBytes(content []byte) ([]Capability, error)
      FilePattern() string  // e.g., "go.mod"
  }

  // Convenience wrapper for local filesystem usage:
  func ParseFile(p DepParser, filePath string) ([]Capability, error) {
      data, err := os.ReadFile(filePath)
      if err != nil { return nil, err }
      return p.ParseBytes(data)
  }
  ```
- `gomod.go` — `GoModParser` implementation using `golang.org/x/mod/modfile` (stdlib-adjacent, pure Go, battle-tested)
- Each `require` directive → one `Capability` with `Category: CatExternalDep`, `Source: LayerDependency`
- ID generation: `dep:go:<module_path>`

**The "Done" test:** Parse a real `go.mod` (TASS's own!) → get back a `[]Capability` with correct entries. Test with a `go.mod` that has `require`, `replace`, and `exclude` blocks.

**Why go.mod first:** It's the simplest structured format AND it's the format you'll use for dogfooding (TASS scanning itself). requirements.txt and package.json come in Phase 2.

---

### Step 1.5 — The `tass init` Command
**⏱ ~3 hours** | **Dependencies: Steps 1.3, 1.4**

Wire together the parser and manifest writer into the first real CLI command. This is the first-run experience from the design doc.

**Deliverables:**
- `tass init [--path <repo-root>]`
  1. Walk the repo root looking for known dependency files
  2. Parse each found file via the appropriate `DepParser`
  3. Aggregate into a `CapabilitySet`
  4. Generate a `tass.manifest.yaml` with all capabilities pre-confirmed (status: `auto_detected`)
  5. Write to repo root
  6. Print summary: "Found N capabilities across M dependency files. Manifest written to tass.manifest.yaml. Review and commit."

**The "Done" test:** Run `tass init` on TASS's own repo (or clone a known OSS Go project). Open the generated YAML. Does it look right? Would you commit this?

**UX note (from the doc):** The generated manifest should include inline comments explaining each section. The design doc says the first-run review should take <15 minutes. Comments like `# Payment processing SDK` next to the Stripe entry help.

---

### Step 1.6 — Phase 1 Integration Test & Smoke Check
**⏱ ~2 hours** | **Dependencies: Step 1.5**

Write a proper end-to-end test and fix whatever's broken.

**Deliverables:**
- `e2e/init_test.go` — creates a temp directory with a synthetic `go.mod`, runs `tass init`, validates the output manifest
- Fix any serialization bugs, path handling issues, edge cases
- Ensure the binary cross-compiles: `GOOS=darwin GOARCH=arm64 go build ./cmd/tass`
- Write a `Makefile` with `build`, `test`, `lint` targets

**The "Done" test:** `make test` is green. You can hand the binary to someone, they run `tass init`, and it works.

---

### Phase 1 Checkpoint 🏁
At this point you have:
- ✅ Compiling Go monorepo with clean package structure
- ✅ Core data contracts shared across all packages
- ✅ Manifest schema that can be read, written, and diffed
- ✅ go.mod dependency parsing producing real capabilities
- ✅ `tass init` generating a manifest from a real repo
- ❌ No Tree-sitter yet, no API, no UI, no storage

**This is the correct state.** You have an end-to-end slice through the init flow. Now we add detection intelligence.

---

## Phase 2: The Nervous System
### *"Teach it to see. Layer 0 diffs, Layer 1 AST queries, and the core detection pipeline."*

Phase 2 is where TASS learns to actually detect capabilities — both from dependency file changes (Layer 0 diff mode) and from source code analysis (Layer 1 Tree-sitter). By the end, `tass scan` produces a complete `CapabilitySet` and diffs it against the manifest.

---

### Step 2.1 — Layer 0 Diff Mode (go.mod base vs. PR)
**⏱ ~3 hours** | **Dependencies: Phase 1 complete**

Step 1.4 parses a single go.mod. Now parse TWO (base branch vs. PR branch) and diff them. This is the "80% of value for 20% of effort" layer.

**Deliverables:**
- `internal/scanner/depdiff.go`:
  ```go
  func DiffDependencies(basePath, prPath string) (added []Capability, removed []Capability, err error)
  ```
- Parse both files, compute set difference
- `added` → new capabilities to flag
- `removed` → capabilities that may need manifest cleanup (informational for now)
- Handle edge cases: file doesn't exist in base (new project), file deleted in PR, `replace` directives

**The "Done" test:** Test with two go.mod fixtures: base has 10 deps, PR has 12 (2 added, 1 removed). Diff returns correct sets.

---

### Step 2.2 — Multi-Language Dependency Parsers
**⏱ ~3 hours** | **Dependencies: Step 2.1**

Extend Layer 0 to cover the big three ecosystems beyond Go.

**Deliverables:**
- `requirements_txt.go` — Python's requirements.txt parser
- `package_json.go` — Node's package.json parser (use `encoding/json`, it's stdlib)
- Each implements the `DepParser` interface
- `registry.go` — a `ParserRegistry` that maps filenames → parsers:
  ```go
  var DefaultRegistry = map[string]DepParser{
      "go.mod":            &GoModParser{},
      "requirements.txt":  &RequirementsTxtParser{},
      "package.json":      &PackageJsonParser{},
  }
  ```
- Diff mode works for all three

**The "Done" test:** Create fixture pairs for each format. Diffs return correct added/removed. Run `tass init` on a repo that has BOTH go.mod and package.json — manifest contains capabilities from both.

**Scope discipline:** Do NOT do Cargo.toml, Gemfile, pom.xml yet. Three ecosystems cover >80% of AI code generation users. More can come from community rules later.

---

### Step 2.3 — Tree-sitter Setup & First Query (Go HTTP)
**⏱ ~3 hours** | **Dependencies: Step 1.1**

This is the "will CGO cooperate on Apple Silicon?" session. Get Tree-sitter compiling and running one query.

**Deliverables:**
- Add `github.com/smacker/go-tree-sitter` and the Go grammar
- `internal/scanner/ast.go`:
  ```go
  type ASTScanner struct {
      parser   *sitter.Parser
      queries  map[string][]*sitter.Query  // language → queries
  }
  // ScanBytes is the primary interface — works on raw file content.
  // This means the same scanner works for local files AND
  // files fetched via GitHub API in Phase 3.
  func (s *ASTScanner) ScanBytes(content []byte, filename string, lang string) ([]Capability, error)

  // ScanFile is a convenience wrapper for local filesystem.
  func (s *ASTScanner) ScanFile(path string, lang string) ([]Capability, error)
  ```
- First query file: `rules/go/http_client.scm`
  ```scheme
  (call_expression
    function: (selector_expression
      operand: (identifier) @pkg
      field: (field_identifier) @method)
    (#match? @pkg "http")
    (#match? @method "Get|Post|Put|Delete|Do"))
  ```
- Parse a Go source file → match HTTP client calls → return as capabilities

**The "Done" test:** Create a fixture Go file with `http.Get("https://example.com")`. Scanner finds it. File without HTTP calls returns empty.

**⚠️ CRITICAL BLINDSPOT: CGO on Apple Silicon.** `go-tree-sitter` uses CGO. On your M4 Pro:
- Ensure Xcode command line tools are installed: `xcode-select --install`
- Set `CGO_ENABLED=1` (should be default on macOS)
- First build will be slow (compiling C tree-sitter core). Subsequent builds are cached.
- If CGO becomes painful, fallback plan: `tree-sitter-go` WASM bindings via `wazero` (pure Go WASM runtime). But try CGO first — it's the happy path.

---

### Step 2.4 — Tree-sitter Query Library (Core Rules)
**⏱ ~3 hours** | **Dependencies: Step 2.3**

Write the initial set of detection rules. Remember: **rules are data, not code.**

**Deliverables in `rules/`:**
```
rules/
├── go/
│   ├── http_client.scm        ← (from 2.3)
│   ├── database_sql.scm       ← database/sql Open, Query, Exec
│   ├── os_file.scm            ← os.Create, os.Open, os.WriteFile
│   └── net_listen.scm         ← net.Listen, net.Dial
├── python/
│   ├── requests.scm           ← requests.get/post/put/delete
│   ├── urllib.scm             ← urllib.request.urlopen
│   ├── sqlite3.scm            ← sqlite3.connect
│   └── open_file.scm          ← open() with write modes
├── javascript/
│   ├── fetch.scm              ← fetch(), axios calls
│   ├── fs.scm                 ← fs.writeFile, fs.readFile
│   └── http_server.scm        ← http.createServer, express()
└── _shared/
    └── README.md              ← How to contribute rules
```

- `internal/scanner/rules.go` — `LoadRules(rulesDir string) (map[string][]*Rule, error)` — walks directory, loads .scm files, maps to languages
- Rule metadata via filename convention or a small YAML sidecar:
  ```yaml
  # rules/go/http_client.scm.meta.yaml
  category: network_access
  name: "HTTP client outbound request"
  confidence: 0.95
  ```

**The "Done" test:** Scanner loads all rules. Runs against fixture files for each language. Detects expected capabilities. No false positives on clean fixtures.

**Blindspot:** Tree-sitter grammars need to be installed per-language. For your M4 Pro dev environment:
- Go grammar: `github.com/smacker/go-tree-sitter/golang`
- Python grammar: `github.com/smacker/go-tree-sitter/python`
- JavaScript grammar: `github.com/smacker/go-tree-sitter/javascript`
- These are all available as Go packages wrapping the C grammars. They'll compile with CGO.

---

### Step 2.5 — Unified Scanner Pipeline
**⏱ ~3 hours** | **Dependencies: Steps 2.2, 2.4**

Merge Layer 0 and Layer 1 into a single scanner that produces one unified `CapabilitySet`.

**Deliverables:**
- `internal/scanner/scanner.go`:
  ```go
  type Scanner struct {
      depParsers  ParserRegistry
      astScanner  *ASTScanner
  }

  // ScanRepo — full repo scan from local filesystem (used by `tass init` and dogfooding)
  func (s *Scanner) ScanRepo(repoRoot string) (*CapabilitySet, error)

  // ScanDiff — diff scan from local filesystem (used by `tass scan` for local dev)
  func (s *Scanner) ScanDiff(repoRoot, baseBranch string) (*CapabilitySet, error)

  // ScanRemote — scan files fetched via API (used by webhook handler in Phase 3)
  // This is just a signature for now — implementation comes in Step 3.4.
  // Because DepParser and ASTScanner both work on []byte, this will
  // be straightforward to implement when the time comes.
  func (s *Scanner) ScanRemote(headFiles map[string][]byte, baseDeps map[string][]byte) (*CapabilitySet, error)
  ```
- `ScanRepo`: walks repo → reads dep files → parses all → reads source files → AST scans all → deduplicates → returns CapabilitySet
- `ScanDiff`: gets changed files (via `git diff --name-only`) → filters to dep files and source files → scans only changed files → diffs deps → returns CapabilitySet of **new** capabilities only. Note: this is the local-only path using git. In production (Phase 3), `ScanRemote` replaces this — the GitHub API provides the changed file list directly.
- Deduplication: if a dependency is found in both go.mod (Layer 0) AND source code (Layer 1), prefer the Layer 0 detection (higher confidence, simpler evidence)

**The "Done" test:** `ScanRepo` on a real Go project returns capabilities from both layers, properly categorized and deduplicated.

---

### Step 2.6 — The `tass scan` Command (Local Dev & Dogfooding)
**⏱ ~2 hours** | **Dependencies: Steps 1.3, 2.5**

Wire the scanner into a local CLI command. In production, scans are triggered by webhooks (Phase 3) — but this CLI command is essential for: (a) testing your scanner during development, (b) dogfooding TASS on real repos, and (c) the eventual v3.1 CLI tool for power users.

**Deliverables:**
- `tass scan [--base <branch>] [--format json|text]`
  1. Load existing `tass.manifest.yaml` (error if not found — must run `tass init` first)
  2. Run `Scanner.ScanDiff()` against base branch
  3. Diff detected capabilities against manifest
  4. Output novel capabilities:
     - `text` format: human-readable summary for terminal
     - `json` format: machine-readable for piping to API/UI
  5. Exit code: 0 if no novel capabilities, 1 if novel capabilities found

**The "Done" test:** Create a git repo, run `tass init`, commit, add a new dependency on a branch, run `tass scan --base main`. See the new dependency flagged. Already-known dependencies are NOT flagged.

---

### Step 2.7 — Phase 2 Integration Test & Dogfooding
**⏱ ~3 hours** | **Dependencies: Step 2.6**

Dogfood TASS on itself and on 2-3 real open-source repos.

**Deliverables:**
- Run `tass init` + `tass scan` on:
  1. TASS itself
  2. A popular Go project (e.g., `minio/minio` or `grafana/grafana`)
  3. A popular Python project (e.g., `fastapi/fastapi`)
- Document: false positives, missed capabilities, scan time
- Fix the top 3 issues found
- `e2e/scan_test.go` — test the full scan flow with synthetic git repos

**The "Done" test:** `tass scan` runs clean on TASS's own repo. Scan time is <30 seconds (the design doc's target). No panic, no crash, no garbage output.

---

### Phase 2 Checkpoint 🏁
At this point you have:
- ✅ Layer 0 dependency diffing for Go, Python, JavaScript
- ✅ Layer 1 Tree-sitter AST queries for core capabilities
- ✅ Unified scanner producing a CapabilitySet (works on both local files AND raw bytes — Phase 3 ready)
- ✅ Manifest diffing identifying novel capabilities
- ✅ `tass init` and `tass scan` CLI commands for local dev and dogfooding
- ❌ No persistence, no API, no UI, no GitHub integration yet

**You can now detect capabilities and identify what's new. The scanner is the hardest part. It's done. Phase 3 wraps it in a hosted service.**

**⏰ Side task before Phase 3:** Register your GitHub App now (`github.com/settings/apps/new`). You need the App ID, private key, and webhook secret before Step 3.2. Takes ~15 minutes. Don't let it become a blocker.


---

## Phase 3: The Platform
### *"You're not building a tool. You're building a SaaS. Internalize this now."*

This is the phase where TASS stops being a CLI experiment and becomes a hosted product. The GitHub App model means: TASS is a service that lives on a server, receives webhooks from GitHub, runs scans, and presents results through a hosted web UI. The developer never installs anything. Ever.

Here's the user journey this phase enables:

```
┌────────────────────────────────────────────────────────────────────┐
│ HOW A DEVELOPER EXPERIENCES TASS (GitHub App Model)                │
│                                                                    │
│  1. Team lead goes to github.com/apps/tass-security               │
│     → clicks "Install" → selects repos → done (30 seconds)        │
│                                                                    │
│  2. Developer opens a PR that adds Stripe SDK                      │
│     → GitHub sends webhook to app.tass.dev                         │
│     → TASS clones repo, runs scanner, diffs manifest               │
│     → TASS posts PR comment + failing GitHub Check                 │
│                                                                    │
│  3. Developer sees comment: "1 new capability detected"            │
│     → Clicks "Review on TASS" link                                 │
│     → Lands on app.tass.dev/verify/scan-abc123                     │
│     → Already authenticated via GitHub OAuth (seamless)            │
│     → Sees verification card → clicks Confirm                     │
│                                                                    │
│  4. TASS commits updated tass.manifest.yaml to the PR branch       │
│     → GitHub Check goes green                                      │
│     → PR is ready to merge                                         │
│                                                                    │
│  ❌ Nobody installed a binary                                      │
│  ❌ Nobody opened a terminal                                       │
│  ❌ Nobody ran a CLI command                                       │
│  ✅ Everyone just used their browser                               │
└────────────────────────────────────────────────────────────────────┘
```

**What this means architecturally:**

The TASS Go binary is still a single binary — but now it's a **web server** that runs on Fly.io (or Railway, or any container platform), not a CLI tool that runs in someone's terminal. The scanner is a library called by the webhook handler, not a CLI command. The verification UI is hosted at `app.tass.dev`, not `localhost:8080`.

```
┌──────────────────────────────────────────────────────────────────┐
│  app.tass.dev (single Go binary on Fly.io)                       │
│                                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  Webhook     │  │  Scanner     │  │  Web App               │  │
│  │  Handler     │→ │  Engine      │→ │  (Templ + HTMX)        │  │
│  │  (PR events) │  │  (Phase 1+2) │  │  Verify UI + Dashboard │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│        ↑                                       ↑                 │
│        │                                       │                 │
│   GitHub Webhooks                      GitHub OAuth              │
│   (PR opened,                          (developer login)         │
│    synchronized)                                                 │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  SQLite + Litestream (persistent volume + S3 backup)         ││
│  │  Multi-tenant: scoped by installation_id / repo              ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

**Why SQLite, not PostgreSQL:** You're a solo dev. SQLite on a Fly.io persistent volume with Litestream backing up to S3 gives you: zero operational overhead, sub-millisecond queries, automatic backups, and it handles thousands of concurrent reads. You switch to PostgreSQL when you have a problem SQLite can't solve (spoiler: that's probably past $1M ARR). This is the same stack that Turso, Litestream's creator, and many YC-backed startups use. It's production-grade.

---

### Step 3.1 — SQLite Storage Layer (Multi-Tenant)
**⏱ ~3 hours** | **Dependencies: Phase 1 contracts**

Same as the original storage concept, but now every table is scoped by `installation_id` (GitHub App installation = one org or user account) and `repo_id`.

**Deliverables in `internal/storage/`:**
- Use `modernc.org/sqlite` (pure Go, no CGO dependency for storage)
- Schema:
  ```sql
  CREATE TABLE installations (
      id INTEGER PRIMARY KEY,           -- GitHub App installation ID
      account_login TEXT NOT NULL,       -- org or user login
      account_type TEXT NOT NULL,        -- "Organization" or "User"
      installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      access_token TEXT,                 -- encrypted, refreshed via JWT
      token_expires_at DATETIME
  );

  CREATE TABLE repositories (
      id INTEGER PRIMARY KEY,           -- GitHub repo ID
      installation_id INTEGER REFERENCES installations(id),
      full_name TEXT NOT NULL,           -- "org/repo"
      default_branch TEXT DEFAULT 'main',
      manifest_sha TEXT,                 -- SHA of last known manifest commit
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE scan_results (
      id TEXT PRIMARY KEY,
      repo_id INTEGER REFERENCES repositories(id),
      pr_number INTEGER NOT NULL,
      commit_sha TEXT NOT NULL,
      base_sha TEXT NOT NULL,
      scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      scan_duration_ms INTEGER,
      capabilities_json TEXT NOT NULL,
      novel_count INTEGER DEFAULT 0,
      status TEXT DEFAULT 'pending' CHECK(status IN ('pending','verified','expired'))
  );

  CREATE TABLE verification_decisions (
      id TEXT PRIMARY KEY,
      scan_id TEXT REFERENCES scan_results(id),
      capability_id TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('confirm', 'revert')),
      justification TEXT,
      decided_by TEXT NOT NULL,          -- GitHub username
      decided_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  ```
- `store.go` — `Store` interface with tenant-scoped queries
- `PRAGMA journal_mode=WAL;` on init (concurrent reads while writing)
- Migrations via Go `embed` package

**The "Done" test:** Create installation → create repo → save scan → save decision → query it back scoped by repo. Round trip works. WAL mode confirmed.

---

### Step 3.2 — GitHub App Registration & JWT Auth
**⏱ ~3 hours** | **Dependencies: Step 3.1**

This is the identity layer. A GitHub App has its own identity, authenticates via JWT, and gets installation-scoped tokens to act on repos.

**Deliverables in `internal/github/`:**
- Register a GitHub App at `github.com/settings/apps/new`:
  - **Permissions:** Contents (read+write, for cloning & committing manifest), Pull Requests (read+write, for comments), Checks (read+write, for check runs), Metadata (read)
  - **Webhook URL:** Your dev tunnel (use `ngrok` or Fly.io dev proxy for local dev)
  - **Webhook events:** `pull_request`, `installation`
  - Download the private key (.pem file)
- `app.go`:
  ```go
  type GitHubApp struct {
      AppID      int64
      PrivateKey *rsa.PrivateKey
      WebhookSecret string
  }
  // GenerateJWT — creates a short-lived JWT for GitHub App auth
  // GetInstallationToken — exchanges JWT for an installation access token
  // These tokens are what you use to call GitHub APIs on behalf of the installed org
  ```
- Use `golang-jwt/jwt/v5` for JWT generation (pure Go, no dependencies)
- Token caching: store installation tokens in SQLite, refresh when expired
- Webhook signature verification (`X-Hub-Signature-256`) — CRITICAL for security

**The "Done" test:** Generate JWT → exchange for installation token → use token to call `GET /repos/{owner}/{repo}` → get a valid response. Webhook signature verification rejects tampered payloads.

**⚠️ Local dev tip:** You need a tunnel for webhooks during development. Options:
- `ngrok http 8080` (free tier, random URL each restart)
- `smee.io` (GitHub's recommended webhook proxy for dev — receives webhooks and replays them to localhost)
- Recommendation: start with smee.io, it's purpose-built for this.

---

### Step 3.3 — Webhook Handler (PR Events)
**⏱ ~3 hours** | **Dependencies: Step 3.2**

When a developer opens or updates a PR, GitHub sends a webhook. TASS receives it, validates it, and kicks off a scan.

**Deliverables:**
- `internal/github/webhook.go`:
  ```go
  func (app *GitHubApp) HandleWebhook(w http.ResponseWriter, r *http.Request)
  // 1. Verify webhook signature
  // 2. Parse event type (X-GitHub-Event header)
  // 3. For "pull_request" events with action "opened" or "synchronize":
  //    a. Look up installation → get token
  //    b. Extract repo, PR number, base SHA, head SHA
  //    c. Enqueue scan job (or run inline for v3.0)
  // 4. For "installation" events:
  //    a. "created" → store new installation
  //    b. "deleted" → mark installation inactive
  ```
- `POST /webhooks/github` route on the server
- For v3.0: run scans in a background goroutine. Respond `202 Accepted` immediately — GitHub webhook timeout is 10 seconds for the response, so you CANNOT block on the scan.
- Pattern: respond `202 Accepted` immediately, process in background goroutine, update GitHub via API when done.

**The "Done" test:** Use smee.io to forward a real PR webhook to localhost. TASS receives it, logs the PR details (repo, PR#, SHAs). No scan yet — just plumbing.

---

### Step 3.4 — Repo Fetching & Scan Pipeline
**⏱ ~4 hours** | **Dependencies: Steps 2.5, 3.3**

When a webhook arrives, TASS needs the code to scan it. This step connects the webhook handler to the scanner from Phase 2.

**Deliverables:**
- `internal/github/fetch.go`:
  ```go
  // FetchChangedFiles — gets the list of changed files in a PR via GitHub API
  // FetchFileContent — downloads individual file content via GitHub API
  // FetchDependencyFiles — specifically fetches go.mod, requirements.txt, etc.
  // For both base and head commits
  ```
- **Critical design decision: Don't clone the full repo.** Use the GitHub API to fetch only the files you need:
  - `GET /repos/{owner}/{repo}/contents/{path}?ref={sha}` for individual files
  - `GET /repos/{owner}/{repo}/pulls/{pr}/files` for the list of changed files
  - This is MUCH faster than `git clone` and avoids disk management on the server
- `internal/scanner/remote.go` — adapt the scanner to work with in-memory file content (not just local filesystem paths):
  ```go
  // ScanRemote — scans files fetched via API
  func (s *Scanner) ScanRemote(files map[string][]byte, baseDeps map[string][]byte) (*CapabilitySet, error)
  ```
- Wire together: webhook → fetch changed files + dep files → scan → diff against manifest → store results

**The "Done" test:** Open a real PR on a test repo → webhook fires → TASS fetches the changed files via API → scanner runs → CapabilitySet stored in SQLite. End-to-end, automated.

**Why fetch-via-API instead of git clone:**
1. No git binary needed on the server
2. No disk space management (cloned repos, cleanup)
3. WAY faster — you only download the files you need
4. Works with GitHub's CDN caching
5. Simpler Docker image (no git)

The trade-off: you can't run `git diff` locally. But you don't need to — the GitHub API gives you the list of changed files directly via the PR endpoint.

**⚠️ DATA SECURITY NOTE:** You are fetching customer source code onto your server. This is fine and expected (every GitHub App that does code analysis does this — Snyk, Semgrep, CodeClimate all work this way). BUT: never write source code to disk or database. Process in-memory, extract the `CapabilitySet`, store only the structured output. The source code should be garbage collected after the scan completes. Document this in your security/privacy page. Enterprise customers WILL ask about this.

---

### Step 3.5 — GitHub Checks & PR Comments
**⏱ ~3 hours** | **Dependencies: Step 3.4**

After scanning, TASS reports results back to GitHub in two ways: a Check Run (pass/fail status on the PR) and a PR comment (human-readable summary with a link to verify).

**Deliverables in `internal/github/`:**
- `checks.go`:
  ```go
  // CreateCheckRun — creates a check run in "in_progress" state
  // UpdateCheckRun — updates to "completed" with conclusion "action_required" or "success"
  // Check output includes: summary text, capability count, link to verification UI
  ```
- `comments.go`:
  ```go
  // CreateOrUpdateComment — creates a PR comment (or updates existing one)
  // Uses a hidden HTML comment <!-- tass-scan-id:xxx --> to find/update existing comments
  ```
- The PR comment template (Markdown):
  ```markdown
  ## 🔍 TASS — 3 New Capabilities Detected

  | # | Capability | Category | Detected In | Layer |
  |---|-----------|----------|-------------|-------|
  | 1 | stripe-go v76 | 📦 Dependency | go.mod:14 | Dep Diff |
  | 2 | HTTP POST (external) | 🌐 Network | payment/client.go:42 | AST |
  | 3 | os.WriteFile | 📁 Filesystem | util/export.go:88 | AST |

  **→ [Review & Verify on TASS](https://app.tass.dev/verify/scan-abc123)**

  <details>
  <summary>What is this?</summary>
  TASS scans PRs for newly introduced capabilities — things your code
  can now DO that it couldn't before. Confirm what you intended,
  revert what you didn't.
  </details>

  <!-- tass-scan:abc123 -->
  ```
- Check Run statuses:
  - **In progress:** "Scanning for new capabilities..."
  - **Action required:** "3 new capabilities need verification" (blocks merge if branch protection enabled)
  - **Success:** "All capabilities verified" or "No new capabilities detected ✅"

**The "Done" test:** Open a PR that adds a new dependency → TASS creates a Check (in_progress → action_required) → PR comment appears with capability table → link to `app.tass.dev/verify/xxx` is present.

**The PR comment is your billboard.** Every developer on the team sees it. This is the viral loop. Make it look CLEAN.

---

### Step 3.6 — Verification Decision Engine
**⏱ ~3 hours** | **Dependencies: Steps 3.4, 3.5**

Same core mechanic as always, but now decisions trigger GitHub API calls: committing the updated manifest and updating the Check Run.

**Deliverables:**
- `POST /api/verify` handler:
  ```json
  {
    "scan_id": "scan-abc123",
    "capability_id": "dep:go:github.com/stripe/stripe-go/v76",
    "decision": "confirm",
    "justification": "Payment processing for checkout flow"
  }
  ```
  - `decided_by` comes from the OAuth session (GitHub username), not the request body
- On **confirm**:
  1. Store VerificationReceipt
  2. If ALL capabilities for this scan are now verified:
     a. Generate updated `tass.manifest.yaml` content
     b. Commit to the PR branch via GitHub API (`PUT /repos/{owner}/{repo}/contents/{path}`)
     c. Update GitHub Check Run → `conclusion: "success"`
     d. Update PR comment → "All capabilities verified ✅"
- On **revert**:
  1. Store VerificationReceipt with "revert" decision
  2. Update Check Run → keeps blocking (conclusion stays `action_required`)
  3. Add a review comment on the PR: "Capability X was flagged for revert. Please review."
- Handle partial verification: some confirmed, some reverted, some still pending

**The "Done" test:** Scan produces 3 capabilities → confirm 2, revert 1 → manifest committed to PR with only the 2 confirmed capabilities → Check updated → PR comment updated with summary.

**This is the magic moment.** Developer clicks two buttons in a browser and TASS commits the manifest update, updates the check, and the PR is ready to merge. Zero terminal, zero manual file editing.

---

### Step 3.7 — Analytics & Override Tracking
**⏱ ~2 hours** | **Dependencies: Step 3.6**

Same as the original analytics, now scoped per installation/org.

**Deliverables:**
- `GET /api/stats?installation_id=xxx` returns per-org stats
- `GET /api/stats?repo_id=xxx` returns per-repo stats
- Override rates per developer, per category, per repo
- Track: scan count, avg scan duration, capabilities detected, confirm rate, revert rate

**The "Done" test:** After several scan/verify cycles across multiple repos, stats are accurate and properly scoped.

---

### Step 3.8 — Phase 3 Integration Test
**⏱ ~2 hours** | **Dependencies: Step 3.7**

Full flow through the platform, end-to-end, no UI.

**Deliverables:**
- `e2e/platform_test.go`:
  1. Simulate a webhook (or use a test GitHub App on a test repo)
  2. Verify scan runs and stores results
  3. Call `POST /api/verify` for each capability
  4. Verify manifest committed to PR branch
  5. Verify Check Run updated to success
  6. Verify stats are correct
- Fix any issues found

**The "Done" test:** The entire pipeline works: webhook → scan → store → verify → commit → check green. Automated.

---

### Phase 3 Checkpoint 🏁
- ✅ Multi-tenant SQLite storage (installation + repo scoped)
- ✅ GitHub App with JWT auth + installation tokens
- ✅ Webhook handler receives PR events and triggers scans
- ✅ Remote file fetching via GitHub API (no git clone)
- ✅ PR comments + GitHub Checks posted automatically
- ✅ Verification decisions commit manifest via GitHub API
- ✅ Override rate tracking per org/repo/developer
- ❌ No web UI yet — but the entire platform works via API

**You now have a headless SaaS.** A PR can trigger a scan and post results. The verification currently only works via API calls. Phase 4 puts a face on it.

---

## Phase 4: The Experience
### *"The product isn't the scanner. The product is the feeling of clicking Confirm and watching the check go green."*

Phase 4 is where TASS becomes something a person actually uses. The hosted verification UI, the GitHub OAuth flow, the dashboard — this is the experience layer on top of the platform you built in Phase 3.

---

### Step 4.1 — GitHub OAuth & Session Management
**⏱ ~3 hours** | **Dependencies: Phase 3 complete**

Developers need to be authenticated to verify capabilities (so TASS knows WHO confirmed what). GitHub OAuth is perfect here — they're already logged into GitHub, so the flow is nearly invisible.

**Deliverables in `internal/auth/`:**
- GitHub OAuth flow:
  1. Developer clicks "Review on TASS" link in PR comment
  2. If not authenticated → redirect to GitHub OAuth → redirect back with token
  3. If already authenticated (cookie) → go straight to verification page
- `oauth.go`:
  ```go
  // GitHub App OAuth (use the same App's OAuth credentials):
  // GET  /auth/github          → redirects to GitHub OAuth page
  // GET  /auth/github/callback → exchanges code for token, creates session
  // POST /auth/logout          → clears session
  ```
- Session management: signed cookies with `gorilla/securecookie` or `gorilla/sessions`
  - Store: GitHub username, avatar URL, access token
  - Expiry: 7 days (re-auth after)
- **Permission check:** on verification pages, verify the authenticated user has access to the repo (via GitHub API — check if user is a collaborator)
- Middleware: `RequireAuth()` middleware for verification and dashboard routes

**The "Done" test:** Visit `app.tass.dev/verify/scan-abc123` → redirected to GitHub OAuth → authorize → redirected back to verification page → your GitHub avatar shows in the header. Subsequent visits skip OAuth (cookie).

**UX magic:** The redirect back should land EXACTLY on the verification page they were trying to reach, not a generic homepage. Store the target URL before OAuth redirect.

---

### Step 4.2 — Templ + Pico CSS Base Layout
**⏱ ~3 hours** | **Dependencies: Step 4.1**

You said you have no clue how to design the UI. Here's the exact recipe — follow it and you'll have a professional-looking app with zero design skills:

- **CSS Framework:** **Pico CSS** (`<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">`). It's classless — styles raw HTML elements beautifully. No Tailwind, no custom CSS.
- **Layout:** Single column, max-width 720px, centered. No sidebar, no nav drawer.
- **Color:** Pico's default light/dark theme. ONE accent color override (teal/cyan — 3 lines of CSS).
- **Icons:** Emoji. 📦 dependency, 🌐 network, 🗄️ database, 📁 filesystem, 🔐 privilege.

**The entire UI is 4 pages:**
1. `/verify/:scan-id` — the verification page (list of capability cards)
2. `/dashboard` — org-level analytics
3. `/dashboard/:repo` — repo-level drill-down
4. `/` — redirect to latest pending or dashboard

**Deliverables:**
- Install Templ: `go install github.com/a-h/templ/cmd/templ@latest`
- `internal/ui/templates/`:
  - `layout.templ` — base HTML shell: Pico CSS CDN, HTMX CDN, header (TASS logo text | org selector | avatar + logout), footer
  - `index.templ` — landing page / redirect logic
- Static assets via Go `embed` (tiny CSS override file)
- Route structure:
  ```
  /                           → redirect to dashboard or latest scan
  /verify/:scan-id            → verification page (authenticated)
  /dashboard                  → org-level dashboard (authenticated)
  /dashboard/:repo            → repo-level dashboard (authenticated)
  /auth/github                → OAuth start
  /auth/github/callback       → OAuth callback
  /api/...                    → API routes
  /webhooks/github            → webhook receiver (no auth — uses signature verification)
  ```
- Set up `templ generate --watch` + `air` for hot reload

**The "Done" test:** Authenticated user visits `app.tass.dev` → sees a clean layout with their GitHub avatar, an org selector, and navigation. Looks professional in both light and dark mode. Zero custom CSS beyond 5 lines.

---

### Step 4.3 — Verification Cards UI
**⏱ ~4 hours** | **Dependencies: Step 4.2**

The core product experience. This is the page developers land on from the PR comment link.

**Wireframe:**
```
┌─────────────────────────────────────────────────────────┐
│  🔍 TASS                    acme-corp ▼    @dev 🔵       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  PR #247: "Add payment processing to checkout"          │
│  opened by @developer · 3 new capabilities · View PR ↗  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  2 of 3 reviewed       │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ 📦 NEW DEPENDENCY                                │    │
│  │ stripe-go v76                                     │    │
│  │ github.com/stripe/stripe-go/v76                   │    │
│  │ Detected in: go.mod (line 14) · Layer 0           │    │
│  │                                                   │    │
│  │ ┌──────────────┐  ┌──────────────┐               │    │
│  │ │ ✅ Confirm    │  │ ↩️ Revert    │               │    │
│  │ └──────────────┘  └──────────────┘               │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │ 🌐 NETWORK ACCESS                                │    │
│  │ HTTP POST to external endpoint                    │    │
│  │ internal/payment/client.go:42 · Layer 1           │    │
│  │                                                   │    │
│  │ ▸ Show evidence                                   │    │
│  │ ┌──────────────┐  ┌──────────────┐               │    │
│  │ │ ✅ Confirm    │  │ ↩️ Revert    │               │    │
│  │ └──────────────┘  └──────────────┘               │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  ┌──────────────────────────────────────────┐           │
│  │ ✅ All capabilities reviewed!             │           │
│  │    Manifest committed to PR branch.       │           │
│  │    Check is now passing.                  │           │
│  └──────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────┘
```

**Deliverables:**
- `verify.templ` — the verification page:
  - PR context header with link back to GitHub
  - Progress bar: "2 of 3 reviewed"
  - Capability cards: emoji badge, name, source, detection layer, collapsible evidence
  - Confirm + Revert buttons (HTMX POST, inline swap)
  - On Revert: justification textarea appears (min 10 chars)
  - When ALL reviewed: success banner + "Manifest committed. Check passing."
- HTMX interactions: each button POSTs to `/api/verify`, card swaps inline. No page reloads.

**The "Done" test:** Open a real PR → TASS comments → click "Review on TASS" → land on verification page → see cards → Confirm all → see success → check GitHub: manifest committed, check green. **Three clicks from PR to verified.**

---

### Step 4.4 — Dashboard (Team Metrics)
**⏱ ~4 hours** | **Dependencies: Steps 3.7, 4.2**

The dashboard answers: "Is TASS working, or are developers rubber-stamping?"

**Deliverables:**
- `dashboard.templ` — org-level:
  - **Summary cards:** Active repos, total scans this month, capabilities detected, confirm/revert ratio
  - **Override rate gauge per developer:** Green (<30%), Yellow (30-50%), Red (>50%)
  - **Recent activity feed:** "PR #247 on org/repo — 3 capabilities, 2 confirmed, 1 reverted"
  - **Per-repo breakdown table:** repo, scans, capabilities, override rate, last scan
  - **Category breakdown:** which types get reverted most?
- `repo_dashboard.templ` — repo drill-down:
  - Current manifest contents
  - Decision history timeline
  - Per-developer stats
- HTMX `hx-trigger="every 30s"` for live refresh on activity feed

**The "Done" test:** Dashboard shows accurate numbers after real scan/verify cycles. A security lead would immediately know if devs are engaging or gaming the system.

---

### Step 4.5 — First-Run Experience (App Installation Flow)
**⏱ ~3 hours** | **Dependencies: Steps 4.2, 3.3**

When someone installs the GitHub App, they need the initial manifest. This replaces the CLI `tass init`.

**Deliverables:**
- Installation webhook handler (`installation.created` event):
  1. Store new installation
  2. For each selected repo: run full scan (ScanRepo equivalent via API file fetching)
  3. Generate `tass.manifest.yaml` content
  4. Create a PR on the repo: "Add TASS manifest (tass.manifest.yaml)"
  5. PR description explains what the manifest is, links to docs
- `setup.templ` — post-install page:
  - "TASS is installed! We've opened a PR on each repo with the initial manifest."
  - List of repos with links to their manifest PRs
  - "Review and merge each PR to activate scanning."
- Edge case: repo already has `tass.manifest.yaml` → skip, activate scanning

**The "Done" test:** Install TASS App on test org → PRs opened automatically on selected repos → each contains a sensible manifest → merge → next PR triggers scanning.

**This is the .gitignore moment.** The manifest PR is "Initialize this repository with a behavioral SBOM."

---

### Step 4.6 — Deployment to Fly.io
**⏱ ~3 hours** | **Dependencies: Steps 4.1-4.5 functionally working locally**

Get the whole thing running in the cloud.

**Deliverables:**
- `Dockerfile` — multi-stage build:
  ```dockerfile
  # Build stage
  FROM golang:1.22-bookworm AS builder
  RUN apt-get update && apt-get install -y gcc  # for CGO/Tree-sitter
  WORKDIR /app
  COPY . .
  RUN CGO_ENABLED=1 go build -o tass ./cmd/tass

  # Runtime stage
  FROM debian:bookworm-slim
  COPY --from=builder /app/tass /usr/local/bin/tass
  COPY --from=builder /app/rules/ /app/rules/
  EXPOSE 8080
  CMD ["tass", "serve", "--port", "8080"]
  ```
- `fly.toml`:
  - Persistent volume for SQLite
  - Health check: `GET /health`
  - Auto-stop: disabled (webhooks must be received 24/7)
- Environment variables (Fly secrets):
  - `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET`
  - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` (OAuth)
  - `SESSION_SECRET`, `DATABASE_PATH`
- **Litestream** (recommended): continuous SQLite replication to S3. Zero data loss if the volume dies.

**The "Done" test:** `fly deploy` succeeds. `app.tass.dev` loads. Full flow works live: PR → scan → comment → verify → commit → green.

**Cost:** Fly.io shared-cpu-1x ($3.19/mo) + 1GB volume ($0.15/mo) + S3 backup (~$0.01/mo) = **under $5/month.** Scales to hundreds of repos before you need to upgrade.

---

### Step 4.7 — End-to-End Integration & Hardening
**⏱ ~3 hours** | **Dependencies: Step 4.6**

Break things on purpose and fix them.

**Deliverables:**
- Edge cases:
  - Repo with no manifest → detect, post helpful comment with link to setup
  - Fork PRs → limited permissions → degrade gracefully (comment without check, explain limitation)
  - Massive PR (500+ files) → scan timeout → partial results + "partial scan" note
  - OAuth session expired mid-verification → seamless re-auth back to same page
  - Concurrent PRs on same repo → separate scans, handled correctly
  - GitHub API rate limiting → exponential backoff, surface to user
  - Webhook replay → idempotent (check if scan exists for this commit SHA)
  - Manifest commit conflict → fetch latest SHA, handle 409 gracefully
- Security: CSRF on forms, rate limiting on verify endpoint, no secrets in logs
- Monitoring: structured logging with `slog`, basic `/metrics` endpoint

**The "Done" test:** Every edge case above handled without crashes or confusing output.

---

### Step 4.8 — Dogfood, Document, Ship
**⏱ ~3 hours** | **Dependencies: Step 4.7**

**Deliverables:**
- Install TASS on 3 real repos via the App. Full flow on each.
- Write:
  - **Landing page** (README or one-page site): what TASS is, 30-second install, screenshot of PR comment + verification UI
  - `MANIFEST.md` — manifest format specification
  - `docs/` — Getting started, FAQ, how detection works
  - GitHub App Marketplace listing copy
- Publish App on GitHub Marketplace (free to list)
- Tag `v3.0.0-alpha.1`

**The "Done" test:** A stranger finds TASS on GitHub Marketplace, installs it in 30 seconds, opens a PR, and gets their first capability detection — without reading any documentation.

---

### Phase 4 Checkpoint 🏁
- ✅ GitHub OAuth — seamless developer authentication
- ✅ Hosted verification UI — cards with Confirm/Revert, zero install
- ✅ Dashboard — team metrics, override rates, per-repo breakdown
- ✅ First-run experience — App install → manifest PRs opened automatically
- ✅ Deployed to Fly.io — live at `app.tass.dev`, under $5/month
- ✅ Hardened — edge cases handled, idempotent, rate-limited
- ✅ Listed on GitHub Marketplace
- ✅ Alpha release tagged

---

## The CLI Question: "When, Not If"

**Build the CLI in v3.1, not v3.0.** It's useful for:
- Local development: "I want to run TASS before pushing"
- Non-GitHub platforms (GitLab, Bitbucket)
- Enterprises that can't install third-party GitHub Apps
- Debugging: "Why did TASS flag this?"

The scanner already exists. Wrapping it in a CLI is a weekend project. But the GitHub App is the product for v3.0.

---

## Partnership & Integration Strategy

### The Big Reframe: You're Selling a Data Format, Not a Tool

The manifest is the product. The scanner generates it. The UI curates it. Partnerships make the manifest MORE VALUABLE by connecting it to more systems.

### Tier 1: Build It Yourself (No Partnership Needed)

| Integration | What It Does | Effort | When |
|-------------|-------------|--------|------|
| **GitHub App** | Primary distribution. Zero install. | In roadmap | Phase 3-4 |
| **Slack Notifications** | Alert on high-risk capability detection | ~4 hours | v3.1 |
| **GitLab Integration** | Same value prop, CLI-based initially | ~1 week | v3.1 |
| **VS Code Extension** | Shows manifest inline in editor | ~1 week | v3.2 |

### Tier 2: Ecosystem Partnerships (After 50+ Installed Orgs)

| Partner Type | Examples | What You Offer | What They Offer |
|-------------|---------|---------------|----------------|
| **SAST/SCA Vendors** | Snyk, Semgrep, Checkmarx | Behavioral context enriching their CVE findings. "This vuln is in a module with network access" is scarier than "this module has a CVE." | Distribution, co-marketing, API integration. |
| **AI Code Gen Tools** | Cursor, Copilot, Cody | Manifest as a constraint file: "Don't generate code that adds undeclared capabilities." Behavioral guardrails for AI agents. | Distribution to every AI coder. The dream. |
| **Cloud Security** | Wiz, Lacework, Orca | Code DECLARES capabilities → runtime SHOWS behaviors → gaps = findings. | Enterprise credibility, CISO access. |
| **CI/CD Platforms** | CircleCI, Jenkins, Bitbucket | Native marketplace integration. | Distribution beyond GitHub. |

### Tier 3: The Standard Play (After 500+ Repos)

Publish `tass.manifest.yaml` as an open spec. Approach OpenSSF or OWASP. If the format becomes a standard, TASS is the reference implementation. Standards are nearly impossible to displace.

### Partnership Playbook

1. **Don't approach anyone until 50 orgs have TASS installed.**
2. **Start with SAST/SCA vendors.** Obvious value exchange.
3. **Lead with the manifest, not the tool.** Partners consume your format.
4. **Build the integration yourself first.** Demo it. Let them decide to productize.
5. **AI code gen = home run, 12-month conversation.**

---

## Critical Dependencies Map

```
Step 1.1 (Scaffolding)
  ├── Step 1.2 (Contracts) ──────────────────────────────────┐
  │     ├── Step 1.3 (Manifest) ─── Step 1.5 (init) ────────┤
  │     └── Step 1.4 (go.mod parser) ─── Step 1.5 ──────────┤
  │                                                          │
  │                                     Step 1.6 (Phase 1 test)
  │
  ├── Step 2.1 (Layer 0 diff) ── Step 2.2 (Multi-lang) ─────┐
  ├── Step 2.3 (Tree-sitter) ── Step 2.4 (Rules) ───────────┤
  │                                                          │
  │                          Step 2.5 (Unified scanner) ─────┤
  │                               Step 2.6 (tass scan) ──────┤
  │                               Step 2.7 (Dogfood) ────────┘
  │
  ├── Step 3.1 (SQLite multi-tenant) ───────────────────────┐
  │    Step 3.2 (GitHub App + JWT) ─────────────────────────┤
  │         Step 3.3 (Webhook handler) ─────────────────────┤
  │              Step 3.4 (Remote scan pipeline) ← CRITICAL ┤
  │              Step 3.5 (Checks + PR comments) ───────────┤
  │                   Step 3.6 (Verify + auto-commit) ──────┤
  │                   Step 3.7 (Analytics) ─────────────────┤
  │                   Step 3.8 (Phase 3 test) ──────────────┘
  │
  └── Step 4.1 (GitHub OAuth) ─────────────────────────────┐
       Step 4.2 (Templ + Pico CSS layout) ─────────────────┤
       Step 4.3 (Verification Cards UI) ← THE PRODUCT ─────┤
       Step 4.4 (Dashboard) ───────────────────────────────┤
       Step 4.5 (First-run install flow) ──────────────────┤
       Step 4.6 (Fly.io deployment) ───────────────────────┤
       Step 4.7 (Hardening) ──────────────────────────────┤
       Step 4.8 (Ship it) ────────────────────────────────┘
```

**Key blocker chains:**
1. **Steps 2.3→2.4 (Tree-sitter/CGO):** Layer 0 is the escape hatch.
2. **Step 3.2 (GitHub App registration):** Register the App as a side task during Phase 2. You need it before testing webhooks.
3. **Step 3.4 (Remote scan pipeline):** The scanner needs a new `ScanRemote` mode for in-memory files. Most architecturally significant change from the CLI model.
4. **Step 4.6 (Fly.io):** Deploy early (even "coming soon") to validate Docker build + webhook delivery. Don't wait.

---

## Blindspot Register

| # | Blindspot | Severity | When It Bites | Mitigation |
|---|-----------|----------|---------------|------------|
| 1 | **CGO + Tree-sitter on Apple Silicon** | 🔴 High | Step 2.3 | Xcode CLI tools. Fallback: wazero WASM. Test early. |
| 2 | **Tree-sitter query precision** | 🟡 Medium | Step 2.4+ | Validate node types. Invest in test fixtures. |
| 3 | **Manifest ID stability** | 🔴 High | Step 1.3 | IDs from stable properties (module path, function signature), NOT line numbers. |
| 4 | **Cross-compiling Go+CGO in Docker** | 🔴 High | Step 4.6 | Use `golang:1.22-bookworm` as build base. Test Dockerfile in Phase 2. |
| 5 | **GitHub webhook delivery/timeouts** | 🟡 Medium | Step 3.3 | Respond `202` immediately, process async. Idempotent handlers (check commit SHA). |
| 6 | **GitHub API rate limiting** | 🟡 Medium | Step 3.4 | 5,000 req/hr per installation. Batch file fetches. Only fetch dep files + changed source. Cache aggressively. |
| 7 | **SQLite on Fly.io persistent volumes** | 🟡 Medium | Step 4.6 | Volumes attach to single machine. Fine for v3.0. Switch to Turso/PostgreSQL when scaling to multi-machine. |
| 8 | **OAuth redirect UX** | 🟢 Low | Step 4.1 | Store target URL before redirect. Return to EXACT page after auth. |
| 9 | **Manifest commit conflicts** | 🟡 Medium | Step 3.6 | Fetch latest SHA before committing. Handle 409 Conflict. |
| 10 | **Webhook dev environment** | 🟡 Medium | Step 3.2 | Use smee.io. Set up day one of Phase 3. |
| 11 | **Fork PR permissions** | 🟡 Medium | Step 4.7 | Restricted token on forks. Degrade gracefully. |
| 12 | **Concurrent PR scans on same repo** | 🟡 Medium | Step 3.4 | Scans independent per PR branch. Test it. |
| 13 | **GitHub App Marketplace review** | 🟢 Low | Step 4.8 | Submit early — reviews take days. Free apps simpler to list. |
| 14 | **Templ version compatibility** | 🟢 Low | Step 4.2 | Pin version. |
| 15 | **Manifest merge-friendliness** | 🟡 Medium | Production | One capability per block, sorted alphabetically. Design in Step 1.3. |
| 16 | **Installation on large orgs (100+ repos)** | 🟡 Medium | Step 4.5 | Initial scan of all repos could take minutes and burn API rate limits. Scan repos in batches, prioritize recently active ones. |
| 17 | **Customer source code on your server** | 🔴 High | Step 3.4 | TASS fetches and parses customer source code. Even though it's in-memory and never written to disk, you ARE processing their code on your infrastructure. **Mitigations:** (1) Process in-memory only, never write source to disk or SQLite — only store the CapabilitySet output. (2) Document this clearly in your privacy policy / security page. (3) Consider SOC2 prep early — enterprise customers WILL ask. (4) In v3.1+, consider an "on-prem" mode where the scanner runs as a GitHub Action inside their infrastructure and only sends the CapabilitySet (not source code) to your hosted service. |

---

## What v3.1 Looks Like (Not This Roadmap)

| Feature | Why | Effort |
|---------|-----|--------|
| **CLI tool** | Power users, GitLab/Bitbucket, enterprises | ~1 week |
| **GitLab integration** | Expand TAM | ~1 week |
| **Paid plans + Stripe billing** | Revenue | ~1 week |
| **Hybrid mode (on-prem scanner)** | Enterprise customers who can't send code to third-party servers. Scanner runs as GitHub Action in THEIR infra, sends only CapabilitySet to your hosted dashboard. Best of both worlds. | ~1.5 weeks |
| **Slack/Teams notifications** | Alert on high-risk capabilities | ~3 days |
| **K8s NetworkPolicy generation** | Competitive moat (from design doc) | ~1 week |
| **VS Code Extension** | Manifest inline in editor | ~1 week |
| **Custom detection rules via UI** | Teams add own Tree-sitter queries | ~2 weeks |
| **Multi-region Fly.io** | Latency + availability | ~3 days |

---

## Session Planning Template

```
Session: [Step Number]
Date: ___________
Goal: [One sentence from "The Done test"]
Time budget: ___ hours

Before I start:
- [ ] Previous step's tests are green
- [ ] I know exactly what "done" looks like
- [ ] I have the relevant dep docs open

After I finish:
- [ ] New tests written and passing
- [ ] `go build ./cmd/tass` still compiles
- [ ] `make test` is green
- [ ] Git commit with descriptive message
```
