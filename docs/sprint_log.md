# TASS Sprint Log

**Project:** Trusted AI Security Scanner  
**Spec version:** 0.1  
**Repo:** `tass-security/tass`

---

## Milestone: Whats-New

**Goal:** Complete the runtime verification subsystem, wire the contract enforcement surface to the CI export path, and close the open AST identity-tracking gaps that cause false novel capabilities on PR re-scans.

**Target:** Production-ready for demo at deploy window (Fly.io `iad` region).

**Critical path:** Tasks 1 → 3 → 5 are sequential. Tasks 2, 4, 6 can run in parallel against their respective dependencies.

---

## Active Breakpoints

### BP-1: Variable scope identity in nested control blocks (Layer 1 AST)

**Status:** Open — blocks accurate revert tracking  
**File:** `internal/scanner/ast.go`  
**Symptom:** When a Tree-sitter rule captures a symbol inside a nested control structure (e.g., an `http.Post` call inside an `if err == nil { for _, item := range items { ... } }` block), the generated capability ID is `ast:go:net/http:client:Post` regardless of nesting depth or enclosing variable bindings. Two calls to `http.Post` with different argument shapes inside the same file collapse to the same ID. The `seen` deduplication map in `ASTScanner.ScanBytes` drops the second match entirely.

**Root cause:**
```go
// internal/scanner/ast.go — current deduplication
seen := map[string]bool{}
for _, match := range matches {
    capID := buildCapID(lang, rule, match)
    if seen[capID] {
        continue   // ← second http.Post in same file is silently dropped
    }
    seen[capID] = true
    caps = append(caps, ...)
}
```

The `buildCapID` function includes `{lang}:{cap_id}:{symbol_text}` but not file-scope position or enclosing binding context. For a rule with `symbol_capture: "method"`, every `http.Post` call in the file maps to the same ID regardless of location.

**Impact surface:**
- `tass scan` and `tass init` both call `ScanBytes` per file. A file with two `http.Post` calls (e.g., one inside a retry loop, one outside) generates only one capability entry. The manifest records one. On the next PR that modifies the retry path only, the cap is already in the manifest — `manifest.Diff` produces no novel entry. Legitimate capability additions are invisible.
- The `verified` / `reverted` decision on the verify page is attached to the deduplicated ID. A revert decision on `ast:go:net/http:client:Post` affects all call sites in the file, not just the one the reviewer saw.

**Fix required:**
Extend the ID formula to include a disambiguating positional suffix when the same symbol appears more than once per file:
```
ast:{lang}:{cap_id}:{symbol}              // first occurrence (unchanged)
ast:{lang}:{cap_id}:{symbol}#2            // second occurrence
ast:{lang}:{cap_id}:{symbol}#N            // Nth occurrence
```
The `seen` map should track `(capID_base, count)` and increment before appending. The manifest diff remains an exact ID match — existing manifested IDs without a suffix remain matched; new numbered variants are novel. This is a backward-compatible change to the ID format.

**Alternate approach (preferred if manifest migration is acceptable):** Include file-relative row:col in the ID:
```
ast:{lang}:{cap_id}:{symbol}:{file_basename}:{line}
```
This removes all collision risk but invalidates every existing Layer 1 ID in committed manifests. Requires a one-time `tass init` re-baseline.

---

### BP-2: Nested `if` scope — wrong enclosing function identity for privilege detection

**Status:** Open — produces incorrect `privilege_pattern` attributions  
**File:** `rules/go/exec_cmd.scm`, `internal/scanner/ast.go`  
**Symptom:** The `exec_cmd` rule matches any `exec.Command(...)` call. When the call appears inside a nested `if` block that itself is inside a function that is a method receiver on a struct containing an auth guard, the capability is attributed to `exec.Command` with no enclosing context. On the verify page, the reviewer sees `"Subprocess execution: exec.Command"` with file and line, but has no information about which method or struct the call is inside, making the `Confirm` / `Revert` decision context-free.

**Root cause:** `.scm` query captures only the direct node matching the pattern. Go rules do not capture the enclosing `func_declaration` or `method_declaration` node.

**Fix required:** Add an optional enclosing-function capture to each `.scm` rule:
```scheme
(function_declaration
  name: (identifier) @enclosing_func
  body: (_
    (call_expression
      function: (selector_expression
        operand: (identifier) @pkg
        field: (field_identifier) @method)
      (#match? @pkg "^exec$")
      (#match? @method "^(Command|CommandContext)$"))))
```
Surface `enclosing_func` text in `Capability.RawEvidence` (append ` in func {name}`) and in the verify card. No ID change needed.

---

### BP-3: Cross-file scope — same cap ID emitted by two files, only one stored

**Status:** Open — manifests for repos with shared HTTP client wrappers are incomplete  
**File:** `internal/scanner/scanner.go` — `ScanRepo`, `ScanDiff`  
**Symptom:** `ScanRepo` walks all source files and calls `ScanBytes` per file, appending results into a flat `CapabilitySet`. The set is keyed by ID (`map[string]Capability`). If `internal/http/client.go` and `internal/payments/gateway.go` both contain `http.Post(...)`, only the second file's entry survives in the set (map overwrite). The first file's location is lost.

**Root cause:**
```go
// internal/scanner/scanner.go — CapabilitySet merge (pkg/contracts)
type CapabilitySet map[string]Capability
// map assignment: last writer wins
cs[cap.ID] = cap
```

**Impact:** The manifest records one entry for `ast:go:net/http:client:Post` with the location of whichever file was processed last. Audit trails, verify page evidence, and policy generation all reference the wrong file. If the first file is later deleted, the manifest still points to the deleted location.

**Fix required:** `CapabilitySet` should store `[]Capability` per ID, not a single `Capability`. `manifest.Diff` should check whether any ID in the set is novel; `ManifestEntry.Locations` should accumulate all call-site locations. This is a schema-visible change — `ManifestEntry.Locations` already supports `[]CodeLocation`, but the engine only ever writes one.

---

### BP-4: Runtime `looksLikeEndpoint` false-negative on numeric-prefix hostnames

**Status:** Open — runtime drift misclassifies some endpoints  
**File:** `internal/runtime/manifest.go` lines 95–110  
**Symptom:** `looksLikeEndpoint` rejects any hostname whose first character is `'0'`–`'9'`. This filters version strings like `1.2.3.4` (correct) but also incorrectly rejects valid hostnames that begin with a digit, such as `0xdata.io`, `123done.example.com`, or any CDN edge hostname beginning with a numeric segment (e.g., `1.api.provider.com`). Such endpoints are silently excluded from `ManifestNeverObserved` and `ObservedNotInManifest` sections, making drift invisible for those destinations.

**Root cause:**
```go
// internal/runtime/manifest.go
if strings.HasPrefix(h, "v") || (len(h) > 0 && h[0] >= '0' && h[0] <= '9') {
    // blanket numeric-prefix rejection
}
```

The intent is to reject dotted version strings like `1.0.0`. The check is too broad.

**Fix required:** Only reject if **all dot-separated labels** are purely numeric (i.e., it looks like an IPv4 dotted-decimal or semver string). The existing `allNumeric` loop inside the block is the right check but is only reached after the first-character gate, which exits early on hostnames like `1.api.stripe.com`.

Corrected logic:
```go
parts := strings.Split(h, ".")
allNumeric := true
for _, p := range parts {
    stripped := strings.TrimLeft(p, "v")
    if stripped == "" { allNumeric = false; break }
    for _, c := range stripped {
        if c < '0' || c > '9' { allNumeric = false; break }
    }
}
if allNumeric {
    return false
}
```
Remove the early `h[0] >= '0'` gate entirely; let the full label scan decide.

---

### BP-5: Contract pattern matching — `path.Match` glob applied to non-path strings

**Status:** Open — contract allow/forbid rules behave unexpectedly on non-URL capability names  
**File:** `internal/contract/contract.go` — `matchesAny`  
**Symptom:** `matchesAny` uses `path.Match(pattern, text)` to evaluate allow/forbid patterns. `path.Match` is designed for filesystem paths; it treats `/` as a special separator and does not match `*` across `/` boundaries. A contract pattern like `*.fly.dev` works correctly for hostname matching but a pattern like `boto3:*` intended to match any boto3 cap ID (`boto3:client:s3`, `boto3:resource:ec2`) fails because `path.Match("boto3:*", "boto3:client:s3")` returns false — `*` does not match `:`.

**Root cause:** `path.Match` semantics are `/`-aware. Cap IDs use `:` as separator. Neither character is the other.

**Fix required:** Replace `path.Match` in `matchesAny` with a bespoke glob that treats `:` as an ordinary character and only gives `*` the "match any sequence excluding nothing" semantics:
```go
func matchGlob(pattern, text string) bool {
    // filepath.Match replacement: * matches any sequence of non-/ chars.
    // For cap IDs we want * to match any sequence including ':'.
    // Use strings.Contains for simple suffix/prefix wildcards; fall back to
    // a hand-rolled DFA for full `*` support.
}
```
Or use `strings.HasPrefix` / `strings.HasSuffix` / `strings.Contains` for the three common pattern shapes (`prefix:*`, `*:suffix`, `*substring*`) and reserve `path.Match` for patterns that contain only `/`-separated segments (URL hostnames).

---

## Completed Work (Whats-New)

| Task | Description | Commit area |
|---|---|---|
| ✅ Runtime VPC flow parser | `internal/runtime/parsers/vpcflow.go` — v2 log format, ACCEPT filter, public IP filter | `internal/runtime/` |
| ✅ Runtime diff engine | `internal/runtime/diff.go` — dedup, DNS resolve, three-section DiffReport | `internal/runtime/` |
| ✅ Runtime manifest extraction | `internal/runtime/manifest.go` — hostname extraction from Name/Note, MatchesManifest | `internal/runtime/` |
| ✅ `tass verify-runtime` CLI | `cmd/tass/runtime.go` — flags, text/JSON output, exit 1 on drift | `cmd/tass/` |
| ✅ `POST /api/runtime-verify` | `internal/server/runtime_verify.go` — HTTP surface for server-side drift check | `internal/server/` |
| ✅ `tass spec --version` | `cmd/tass/spec.go` — prints `0.1`, embeds JSON schemas | `cmd/tass/` |
| ✅ `tass validate-manifest` | `cmd/tass/spec.go` — YAML→JSON normalize, jsonschema validation | `cmd/tass/` |
| ✅ Contract enforcement in scan CLI | `cmd/tass/scan.go` — loads `tass.contract.yaml`, prints violations, exits 2 | `cmd/tass/` |
| ✅ Python AI/ML rules | `rules/python/{boto3,strands_agent,fastmcp,opentelemetry}.*` | `rules/python/` |
| ✅ Audit hash chain | `internal/audit/{log,chain}.go` — SHA-256 chain, VerifyChain, compliance mapping | `internal/audit/` |
| ✅ Manifest history table | `internal/storage/migrations/004_manifest_history.sql`, `SaveManifestSnapshot` | `internal/storage/` |
| ✅ Compliance report PDF | `internal/compliance/{report,pdf}.go` — deterministic hash, three render formats | `internal/compliance/` |
| ✅ Dashboard redesign | `internal/ui/templates/dashboard.templ` — stat grid, recent scans, dev rates | `internal/ui/` |
| ✅ Verify page HTMX OOB | `internal/ui/templates/verify.templ` — progress bar + success banner OOB swap | `internal/ui/` |
| ✅ Custom CSS design system | `internal/ui/static/style.css` — dark mode, badge pills, cards, no Pico CSS | `internal/ui/` |
| ✅ `tass seed` | `cmd/tass/seed.go` — 1 installation, 3 repos, 8 scans, 25 decisions | `cmd/tass/` |
| ✅ RBAC + PermCache | `internal/auth/rbac.go` — Viewer < Developer < Approver < Admin, 5-min TTL | `internal/auth/` |

---

## Open Tasks (Whats-New)

| # | Task | Owner | Blocking |
|---|---|---|---|
| 1 | Fix BP-1: positional ID suffix for same-symbol dedup | — | BP-3 |
| 2 | Fix BP-4: `looksLikeEndpoint` numeric-prefix gate | — | — |
| 3 | Fix BP-5: `matchesAny` glob semantics for `:` separators | — | — |
| 4 | Add enclosing-function context to privilege caps (BP-2) | — | — |
| 5 | Multi-location accumulation in CapabilitySet (BP-3) | — | BP-1 |
| 6 | Worker pool for runtime DNS resolution (AP-2) | — | — |
| 7 | `go test ./...` passing clean after BP-1 + BP-3 fixes | — | 1, 5 |
| 8 | Fly.io deploy + post-deploy smoke test | — | 7 |

---

## Test Checkpoints

After each BP fix, the following must pass before marking the task complete:

```bash
make generate
go build ./cmd/tass
go test ./...
```

**Per-fix regression targets:**

| Fix | Test file(s) to run |
|---|---|
| BP-1 (ID dedup) | `internal/scanner/` (add new case: two `http.Post` calls in one file → expect 2 caps) |
| BP-2 (enclosing func) | `internal/scanner/` (verify `RawEvidence` includes `in func ...`) |
| BP-3 (cross-file merge) | `internal/scanner/` (two files, same cap ID → expect `Locations` length 2) |
| BP-4 (hostname filter) | `internal/runtime/` (`runtime_test.go` — add `1.api.example.com` fixture) |
| BP-5 (glob semantics) | `internal/contract/` (add `boto3:*` pattern test against `boto3:client:s3`) |

---

## Known Deferred (Not Whats-New)

| Item | Reason deferred |
|---|---|
| `// indirect` Go dep tracking (AP-4) | Requires manifest schema change; targeting next milestone |
| Base-branch AST diff to eliminate AP-1 false positives | Requires GitHub Contents API call per changed file; cost TBD |
| Parallel per-file AST scan (AP-6) | Blocked on per-goroutine parser instantiation analysis |
| `hostnamesFromEntry` reads `Locations` (AP-5) | Requires manifest YAML schema addition for `endpoints:` field |
