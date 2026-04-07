# TASS v3.0 — "The Disagreement Engine"
## Step-by-Step Implementation Roadmap

> **Architect:** Team Blue Hearts (Principal Architect)
> **Developer:** S (Solo Founder)
> **Stack:** Go. Literally. Just that.
> **Machine:** MacBook M4 Pro (Apple Silicon)
> **Philosophy:** Walking Skeleton → Flesh on Bones → Muscles → Skin

---

## Roadmap Overview

| Phase | Name | Sessions | Cumulative Outcome |
|-------|------|----------|--------------------|
| 1 | **The Skeleton** | 6 steps (~16 hrs) | Go monorepo + manifest schema + core types compiling. `tass init` generates a manifest from a real repo. |
| 2 | **The Nervous System** | 7 steps (~20 hrs) | Full scanner pipeline: Layer 0 (dep diffing) + Layer 1 (Tree-sitter AST) producing a `CapabilitySet`. Manifest diffing identifies novel capabilities. |
| 3 | **The Brain** | 6 steps (~16 hrs) | API backend + SQLite storage + decision engine. Capabilities flow from scan → diff → store. Verification decisions (confirm/revert) persist and update the manifest file. |
| 4 | **The Face** | 6 steps (~18 hrs) | HTMX + Templ UI. Full end-to-end flow: `tass scan` → novel capabilities → verification cards → confirm/revert → manifest updated. CLI polish + first-run experience. |

**Total: 25 steps, ~70 hours, ~4-5 weeks at ~3 sessions/day**

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
  cmd/tass/           → main.go (CLI entrypoint)
  internal/scanner/   → Scanner package (detection engine)
  internal/brain/     → Brain package (API + decision engine)
  internal/ui/        → UI package (Templ + HTMX handlers)
  internal/storage/   → SQLite storage layer
  pkg/manifest/       → Manifest read/write/diff (public API)
  pkg/contracts/      → Shared types (CapabilitySet, VerificationReceipt, etc.)
  rules/              → Tree-sitter .scm query files (data, not code)
  ```
- Minimal `main.go` with a stub CLI using `cobra` or just `os.Args` (keep it dead simple — cobra can come later)
- `go build ./cmd/tass` compiles and produces a binary

**The "Done" test:** `./tass --version` prints `tass v3.0.0-dev`.

**Notes:**
- Do NOT reach for cobra/viper yet unless you already have muscle memory. A `switch os.Args[1]` is fine for now. You're going to refactor this 4 times anyway.
- Keep `pkg/` for things that external consumers (future SDK, manifest tooling) might import. Keep `internal/` for everything else.

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
      Parse(filePath string) ([]Capability, error)
      FilePattern() string  // e.g., "go.mod"
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

  // ScanRepo — full repo scan (used by `tass init`)
  func (s *Scanner) ScanRepo(repoRoot string) (*CapabilitySet, error)

  // ScanDiff — diff scan (used by `tass scan` on PR)
  func (s *Scanner) ScanDiff(repoRoot, baseBranch string) (*CapabilitySet, error)
  ```
- `ScanRepo`: walks repo → finds dep files → parses all → finds source files → AST scans all → deduplicates → returns CapabilitySet
- `ScanDiff`: gets changed files (via `git diff --name-only`) → filters to dep files and source files → scans only changed files → diffs deps → returns CapabilitySet of **new** capabilities only
- Deduplication: if a dependency is found in both go.mod (Layer 0) AND source code (Layer 1), prefer the Layer 0 detection (higher confidence, simpler evidence)

**The "Done" test:** `ScanRepo` on a real Go project returns capabilities from both layers, properly categorized and deduplicated.

---

### Step 2.6 — The `tass scan` Command
**⏱ ~2 hours** | **Dependencies: Steps 1.3, 2.5**

Wire the scanner into the CLI. This is the command that runs in CI.

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
- ✅ Unified scanner producing a CapabilitySet
- ✅ Manifest diffing identifying novel capabilities
- ✅ `tass init` and `tass scan` CLI commands working
- ❌ No persistence, no API, no UI

**You can now detect capabilities and identify what's new. The scanner is the hardest part. It's done.**

---

## Phase 3: The Brain
### *"Give it memory. SQLite storage, HTTP API, decision persistence."*

Phase 3 adds the "brain" — the API backend that stores decisions, manages verification state, and provides the data layer the UI will consume.

---

### Step 3.1 — SQLite Storage Layer
**⏱ ~3 hours** | **Dependencies: Phase 1 contracts**

Set up SQLite with the pure-Go driver. No CGO needed here (we already have CGO from Tree-sitter, but the storage layer should be independently pure).

**Deliverables in `internal/storage/`:**
- Use `modernc.org/sqlite` (pure Go, no CGO — per the design doc)
- Schema:
  ```sql
  CREATE TABLE scan_results (
      id TEXT PRIMARY KEY,
      repo TEXT NOT NULL,
      commit_sha TEXT,
      scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      capabilities_json TEXT NOT NULL  -- JSON blob of CapabilitySet
  );

  CREATE TABLE verification_decisions (
      id TEXT PRIMARY KEY,
      scan_id TEXT REFERENCES scan_results(id),
      capability_id TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('confirm', 'revert')),
      justification TEXT,
      decided_by TEXT,
      decided_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE manifest_history (
      id TEXT PRIMARY KEY,
      repo TEXT NOT NULL,
      version INTEGER NOT NULL,
      manifest_yaml TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_by TEXT
  );
  ```
- `store.go` — `Store` interface with methods: `SaveScanResult`, `SaveDecision`, `GetPendingCapabilities`, `GetDecisionHistory`
- Migrations via embedded SQL files (`embed` package)

**The "Done" test:** Create store → save a scan result → save a decision → query it back. Round trip works.

**Why pure Go SQLite:** The design doc explicitly calls for `modernc.org/sqlite`. This is a transpiled-from-C pure Go SQLite. It's slower than CGO sqlite3 but it means your storage layer compiles anywhere with `CGO_ENABLED=0`. Since Tree-sitter requires CGO anyway, this is more about principle than practice — but it keeps your options open for a future where Tree-sitter goes WASM.

---

### Step 3.2 — HTTP API Skeleton (Chi Router)
**⏱ ~2 hours** | **Dependencies: Step 3.1**

Stand up the HTTP API that the UI will talk to. The design doc says Chi or stdlib — I'd go Chi for the middleware story, but stdlib `net/http` is perfectly fine too.

**Deliverables in `internal/brain/`:**
- `api.go`:
  ```go
  // Routes:
  // POST /api/scan          — receive a CapabilitySet, diff against manifest, return novel capabilities
  // GET  /api/pending        — get all pending (unverified) capabilities
  // POST /api/verify         — submit a VerificationReceipt
  // GET  /api/manifest       — get current manifest
  // GET  /api/stats          — override rates, decision history
  ```
- `tass serve [--port 8080]` CLI command that starts the HTTP server
- Wire routes to storage layer (stub responses are fine for now)

**The "Done" test:** `tass serve` starts. `curl localhost:8080/api/pending` returns `[]`. No crash.

---

### Step 3.3 — Scan → Diff → Store Pipeline
**⏱ ~3 hours** | **Dependencies: Steps 2.5, 3.1, 3.2**

Wire the scanner into the API. When a scan is submitted, the brain diffs against the manifest and stores the results.

**Deliverables:**
- `POST /api/scan` handler:
  1. Receives repo path (or CapabilitySet JSON directly)
  2. Runs scanner (or accepts pre-scanned results)
  3. Loads manifest from repo
  4. Diffs: novel capabilities identified
  5. Stores scan result in SQLite
  6. Returns novel capabilities as JSON
- `GET /api/pending` returns all capabilities awaiting verification

**The "Done" test:** POST a scan → GET pending → see the novel capabilities. The data flows through.

---

### Step 3.4 — Verification Decision Engine
**⏱ ~3 hours** | **Dependencies: Step 3.3**

The core interaction: developer confirms or reverts a capability.

**Deliverables:**
- `POST /api/verify` handler:
  ```json
  {
    "capability_id": "dep:go:github.com/stripe/stripe-go/v76",
    "decision": "confirm",
    "justification": "Payment processing for checkout flow",
    "decided_by": "developer@example.com"
  }
  ```
- On **confirm**: 
  1. Store VerificationReceipt
  2. Add capability to manifest in memory
  3. Write updated `tass.manifest.yaml` to disk
  4. Return success
- On **revert**:
  1. Store VerificationReceipt with "revert" decision
  2. Return success + flag for PR review
- Manifest versioning: increment version counter, store snapshot in `manifest_history`

**The "Done" test:** Submit scan → verify one capability as "confirm" → check manifest file on disk → new capability is there. Verify another as "revert" → it's NOT in the manifest.

**This is the core mechanic.** The entire product is this loop. Make sure it feels rock solid.

---

### Step 3.5 — Analytics & Override Tracking
**⏱ ~2 hours** | **Dependencies: Step 3.4**

The design doc explicitly calls out tracking override rates to prevent TASS from becoming a rubber stamp itself.

**Deliverables:**
- `GET /api/stats` returns:
  ```json
  {
    "total_scans": 47,
    "total_capabilities_detected": 156,
    "total_confirmed": 89,
    "total_reverted": 67,
    "override_rate": 0.57,
    "by_developer": {
      "dev@example.com": { "confirmed": 45, "reverted": 35, "rate": 0.56 }
    },
    "by_category": {
      "external_dependency": { "confirmed": 60, "reverted": 20 },
      "network_access": { "confirmed": 15, "reverted": 30 }
    }
  }
  ```
- `internal/storage/` — add aggregate query methods

**The "Done" test:** After several test verifications, `GET /api/stats` returns accurate numbers.

---

### Step 3.6 — Phase 3 Integration Test
**⏱ ~2 hours** | **Dependencies: Step 3.5**

Full flow through the brain, end-to-end, no UI.

**Deliverables:**
- `e2e/brain_test.go`:
  1. Start TASS server (in-process)
  2. POST a scan result
  3. GET pending capabilities
  4. POST verify (confirm 2, revert 1)
  5. GET pending (should be empty)
  6. Check manifest file (2 new entries)
  7. GET stats (numbers correct)
- Fix any issues found

**The "Done" test:** The entire decision pipeline works via HTTP API. You could build ANY frontend on top of this.

---

### Phase 3 Checkpoint 🏁
- ✅ SQLite storage for scans, decisions, manifest history
- ✅ HTTP API serving the full verification workflow
- ✅ Confirm → manifest updated on disk
- ✅ Revert → capability flagged, not added to manifest
- ✅ Override rate tracking per developer
- ❌ No UI — but the API is complete

---

## Phase 4: The Face
### *"Make it real. HTMX + Templ UI, CLI polish, end-to-end verification flow."*

Phase 4 is where TASS becomes a product someone can actually use. The HTMX + Templ UI, the polished CLI experience, and the first-run flow all come together.

---

### Step 4.1 — Templ Setup & Base Layout
**⏱ ~3 hours** | **Dependencies: Phase 3 complete**

Set up the Templ templating system and create the base HTML layout.

**Deliverables:**
- Install `templ`: `go install github.com/a-h/templ/cmd/templ@latest`
- `internal/ui/templates/`:
  - `layout.templ` — base HTML shell with HTMX CDN, minimal CSS (consider Pico CSS or classless — zero build step)
  - `index.templ` — landing/dashboard page
- `internal/ui/handlers.go` — HTTP handlers that render templates
- Wire into the existing Chi router: UI routes at `/`, API routes at `/api/`
- `templ generate` runs clean, templates compile into Go

**The "Done" test:** `tass serve` → open `http://localhost:8080` → see a styled page that says "TASS — Verification Dashboard" with zero JavaScript build tools.

**Tech choice note:** Templ generates type-safe Go code from templates. This means your templates get compiler checks — a typo in a struct field name is a compile error, not a runtime surprise. This is the single-binary philosophy extended to the UI.

---

### Step 4.2 — Verification Cards UI
**⏱ ~3 hours** | **Dependencies: Step 4.1**

The core UI component: a card for each novel capability with Confirm/Revert buttons.

**Deliverables:**
- `verification_card.templ`:
  - Shows: capability name, category badge, detection layer, file location, raw evidence snippet
  - Two buttons: ✅ Confirm | ↩️ Revert
  - Optional justification text input (appears on click, min 10 chars for revert per the design doc)
  - HTMX: buttons POST to `/api/verify` and swap the card with a "Decision recorded" confirmation
- `pending.templ` — list of all pending verification cards
- `GET /pending` → renders the pending page with all unverified capabilities

**The "Done" test:** Trigger a scan with novel capabilities → navigate to `/pending` → see cards → click Confirm → card updates inline (no page reload) → check manifest file is updated.

**UX from the design doc:** "Developers see a detected capability and click Confirm or Revert — no forms, no questionnaires, just a binary decision." Keep it exactly this simple.

---

### Step 4.3 — Exception Dashboard
**⏱ ~3 hours** | **Dependencies: Steps 3.5, 4.1**

The dashboard showing aggregate decisions and override rates.

**Deliverables:**
- `dashboard.templ`:
  - Summary stats: total scans, capabilities detected, confirm rate, revert rate
  - Per-developer table: name, confirm count, revert count, override rate
  - Per-category breakdown
  - Visual indicator when override rate > 50% (the design doc's alarm threshold)
- `GET /dashboard` → renders with data from `GET /api/stats`
- Use HTMX `hx-trigger="every 30s"` for live-ish refresh if the page is kept open

**The "Done" test:** After running several scan/verify cycles, dashboard shows accurate numbers. High override rates are visually flagged.

---

### Step 4.4 — CLI Polish & First-Run Experience
**⏱ ~3 hours** | **Dependencies: All previous steps**

Make the CLI commands feel finished. This is the difference between "it works" and "it works and I'd recommend it."

**Deliverables:**
- `tass init`:
  - Colorized output (use `fatih/color` or ANSI codes)
  - Progress indicator while scanning
  - Summary table of detected capabilities by category
  - Prompt: "Review tass.manifest.yaml and commit it to your repository."
- `tass scan`:
  - Clear output: "Found N novel capabilities (M confirmed in manifest, K new)"
  - Exit code 0/1 for CI integration
  - `--json` flag for machine consumption
- `tass serve`:
  - Prints URL: "TASS verification UI running at http://localhost:8080"
  - Graceful shutdown on SIGINT
- `tass version` — prints version, commit SHA, build date
- `tass help` — clean, concise help text

**The "Done" test:** Run through the entire flow as a new user: `tass init` → review manifest → commit → make changes → `tass scan` → `tass serve` → verify in browser → manifest updated. The whole thing takes <5 minutes.

---

### Step 4.5 — End-to-End Integration & Hardening
**⏱ ~3 hours** | **Dependencies: Step 4.4**

The final integration pass. Fix everything that's broken. Handle edge cases.

**Deliverables:**
- Edge case handling:
  - No `tass.manifest.yaml` found → helpful error with `tass init` suggestion
  - Empty manifest (no capabilities) → handle gracefully
  - Scanner finds zero novel capabilities → "All clear!" message
  - Malformed YAML → clear error message with line number
  - Git not available → graceful degradation (scan without diff)
  - Binary run outside a git repo → handle gracefully
- Error messages follow UX principles from the doc: helpful, not punitive
- `e2e/full_flow_test.go` — the entire journey, automated
- README.md with installation, quickstart, and a GIF/screenshot

**The "Done" test:** You can hand the binary to someone with zero context, and they can get value from it in under 5 minutes.

---

### Step 4.6 — Dogfood, Document, Ship
**⏱ ~3 hours** | **Dependencies: Step 4.5**

Final dogfooding session and documentation.

**Deliverables:**
- Run TASS on 3 real repositories end-to-end (including TASS itself)
- Document any discovered issues as GitHub issues for v3.1
- Write:
  - `README.md` — installation, quickstart, how it works
  - `MANIFEST.md` — manifest format specification (the open spec from the design doc)
  - `CONTRIBUTING.md` — how to write detection rules (.scm files)
- Build release binary: `goreleaser` config or simple `go build -ldflags` script
- Tag `v3.0.0-alpha.1`

**The "Done" test:** `v3.0.0-alpha.1` is tagged. Binary works on macOS ARM64. Manifest spec is documented. You could post this on Hacker News tomorrow and not be embarrassed.

---

### Phase 4 Checkpoint 🏁
- ✅ HTMX + Templ verification UI with capability cards
- ✅ Confirm/Revert inline with HTMX (zero page reloads)
- ✅ Exception dashboard with override rate tracking
- ✅ Polished CLI: `tass init`, `tass scan`, `tass serve`
- ✅ Full end-to-end flow working
- ✅ Alpha release tagged

---

## Critical Dependencies Map

```
Step 1.1 (Scaffolding)
  ├── Step 1.2 (Contracts) ──────────────────────────────┐
  │     ├── Step 1.3 (Manifest) ─── Step 1.5 (init) ────┤
  │     └── Step 1.4 (go.mod parser) ─── Step 1.5 ──────┤
  │                                                      │
  │                                     Step 1.6 (Phase 1 test)
  │
  ├── Step 2.1 (Layer 0 diff) ── Step 2.2 (Multi-lang) ─┐
  ├── Step 2.3 (Tree-sitter) ── Step 2.4 (Rules) ───────┤
  │                                                      │
  │                          Step 2.5 (Unified scanner) ─┤
  │                               Step 2.6 (tass scan) ──┤
  │                               Step 2.7 (Dogfood) ────┘
  │
  ├── Step 3.1 (SQLite) ── Step 3.2 (API skeleton) ─────┐
  │                          Step 3.3 (Scan pipeline) ───┤
  │                          Step 3.4 (Verify engine) ───┤
  │                          Step 3.5 (Analytics) ───────┤
  │                          Step 3.6 (Phase 3 test) ────┘
  │
  └── Step 4.1 (Templ) ── Step 4.2 (Cards UI) ──────────┐
                           Step 4.3 (Dashboard) ─────────┤
                           Step 4.4 (CLI polish) ────────┤
                           Step 4.5 (Hardening) ─────────┤
                           Step 4.6 (Ship it) ───────────┘
```

**The only true blocker chain:** Steps 2.3→2.4 (Tree-sitter setup). If CGO fights you, everything in Phase 2 Layer 1 stalls. Mitigation: Step 2.1 and 2.2 (Layer 0) are completely independent of Tree-sitter. You can ship a Layer-0-only TASS while debugging CGO issues.

---

## Blindspot Register

| # | Blindspot | Severity | When It Bites | Mitigation |
|---|-----------|----------|---------------|------------|
| 1 | **CGO + Tree-sitter on Apple Silicon** | 🔴 High | Step 2.3 | Have Xcode CLI tools ready. Fallback: wazero WASM runtime. Test early. |
| 2 | **Tree-sitter query precision** | 🟡 Medium | Step 2.4+ | Queries will have false positives. `http` matches string "http" in comments. Need to validate node types carefully. Invest in test fixtures. |
| 3 | **Git operations from Go** | 🟡 Medium | Step 2.5 | `git diff` via `os/exec` is fine. Don't reach for `go-git` unless you need to avoid the git binary dependency. Shell out first. |
| 4 | **Manifest ID stability** | 🔴 High | Step 1.3 | If capability IDs change between scans (e.g., due to line number changes), the diff breaks. IDs MUST be derived from stable properties (module path, function signature) NOT from volatile properties (line numbers, file offsets). |
| 5 | **Templ version compatibility** | 🟢 Low | Step 4.1 | Templ is pre-1.0. Pin your version. `go install github.com/a-h/templ/cmd/templ@v0.2.x` |
| 6 | **SQLite concurrent access** | 🟡 Medium | Step 3.1 | Single-user local dev = fine. If two scans run simultaneously, you'll hit SQLite locks. Set WAL mode: `PRAGMA journal_mode=WAL;` in your init. |
| 7 | **Manifest merge conflicts** | 🟡 Medium | Production use | Two developers confirm different capabilities → merge conflict in YAML. Solution: design the YAML format to be merge-friendly (one capability per block, sorted alphabetically). Think about this in Step 1.3. |
| 8 | **Scan time on large repos** | 🟡 Medium | Step 2.7 | Tree-sitter is fast, but scanning 10K files will take time. Only scan changed files in diff mode. Full-repo scan (init) can be slower — it's a one-time cost. |
| 9 | **HTMX + Templ hot reload** | 🟢 Low | Step 4.1 | Use `templ generate --watch` + `air` for hot reload during UI development. Set this up at the start of Phase 4 or you'll waste time restarting the server. |
| 10 | **No auth on the local server** | 🟢 Low | Step 3.2 | Local-only dev server has no auth. Fine for v1. Flag for v3.1 if you add CI mode where the server is exposed. |

---

## Session Planning Template

Use this for each 2-4 hour sitting:

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

---

*"The best architecture is the one that lets a solo developer ship a working product before the market window closes. This roadmap is designed for exactly that."*

— Team Blue Hearts 💙, Principal Architect, TASS v3.0
