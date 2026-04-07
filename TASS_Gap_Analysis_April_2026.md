# TASS v3.0 / v3.1 — Gap Analysis & Implementation Punch List
### Prepared by Team Blue Hearts 💙 — April 6, 2026

---

## Executive Summary

The flight-recorder repo is **substantially complete for v3.0**. The core pipeline (webhook → scan → diff → PR comment → Check Run → verify → commit manifest) is fully wired end-to-end. What remains is mostly polish, missing features from the v3.1 plan, and a UI that needs a serious glow-up.

**Code stats:** ~12,000 lines of Go across 50+ files. 4 Templ templates, 12 Tree-sitter rules, 3 SQL migrations, full e2e test scaffolding.

---

## PART 1: v3.0 Completion Gaps

These are things the v3.0 roadmap specified that are either missing or broken.

### 1.1 — Bugs & Broken Behavior

| Issue | File | Severity | Fix Estimate |
|-------|------|----------|-------------|
| `repoFullName()` in verify.templ always returns `""` — the "View PR ↗" link is dead | `internal/ui/templates/verify.templ` | High | 30 min. Store `FullName` on `ScanResult` or pass through from storage join |
| FirstRun pipeline only scans dep files, not source files — initial manifest misses AST detections | `internal/github/firstrun.go` → `collectDepFiles()` | Medium | 1 hr. Add source file collection + AST scan pass to `processRepo()` |
| `.DS_Store` and `.history/` committed to repo | Root | Low | 10 min. Add to `.gitignore`, `git rm --cached` |
| `SaveDecision` uses INSERT not INSERT OR REPLACE — double-clicking Confirm/Revert will error | `internal/storage/storage.go` | Medium | 15 min. Add `ON CONFLICT(id) DO UPDATE` or upsert logic |
| HTMX verify POST returns full card HTML but progress bar doesn't update without a page reload | `internal/ui/handlers.go` + verify.templ | Medium | 1 hr. The `CapabilityCardFragment` has OOB swap for progress but needs the handler to actually return it |

### 1.2 — Missing v3.0 Features (per Roadmap Phases 1-4)

| Feature | Roadmap Step | Status | Work Required |
|---------|-------------|--------|---------------|
| CLI colorized output (`fatih/color`) | Step 4.4 | ❌ Missing | 1 hr. Add color to `tass init` and `tass scan` output |
| Progress indicator during `tass init` scan | Step 4.4 | ❌ Missing | 30 min |
| `tass version` with commit SHA + build date | Step 4.4 | ❌ Missing | 30 min. Add `-ldflags` to Makefile |
| Edge case: malformed YAML error with line number | Step 4.5 | ❌ Missing | 30 min |
| Edge case: binary run outside git repo | Step 4.5 | ❌ Missing | 30 min |
| Edge case: git not available graceful degradation | Step 4.5 | ❌ Missing | 30 min |
| `e2e/full_flow_test.go` (the entire journey automated) | Step 4.5 | ❌ Partial — `e2e/` has init, scan, and platform tests but not the full webhook→verify→manifest flow | 3 hrs |
| Justification field — min 10 char requirement for confirms | Design Doc §11 | ❌ Missing | The verify UI has no justification input at all. The API accepts it but the UI never sends it | 1 hr |
| Override rate > 50% escalation/alert | Design Doc §11 | ❌ Missing | Dashboard shows the rate with color coding but there's no notification or blocking mechanism | 2 hrs (v3.1 scope honestly) |
| Demo seed script | v3.1 §1.4 | ❌ Missing | 2 hrs. Write a Go script or SQL file that inserts realistic scan + decision data |

### 1.3 — Test Coverage Gaps

| Area | Current | Gap |
|------|---------|-----|
| Scanner (Layer 0 + Layer 1) | ✅ Good — `depdiff_test.go`, `ast_test.go`, `rules_test.go`, `scanner_test.go` | Python and JS rules lack dedicated test files |
| GitHub API layer | ✅ Good — `app_test.go`, `checks_test.go`, `comments_test.go`, `fetch_test.go`, `handler_test.go`, `verifier_test.go` | Missing: `firstrun_test.go`, `pipeline_test.go` |
| Storage | ✅ Good — `storage_test.go` | Missing: analytics query accuracy tests (GetStats, GetStatsByInstallation) |
| Contracts + Manifest | ✅ Good — both have test files | — |
| Server + Verify | ✅ `verify_test.go` exists | Missing: rate limiter tests, middleware tests |
| UI | ❌ Zero template tests | Not critical for demo but needed before design partner |

---

## PART 2: The UI Problem

You're right that it's clunky. Here's the diagnosis.

### What's Actually Wrong

**The verify page** is the product's hero screen — it's where the core mechanic lives — and right now it looks like a homework assignment built with Pico CSS defaults. Specific issues:

1. **No justification input.** The roadmap says "optional justification text" but the UI has zero text input. A developer clicks Confirm and there's no way to say *why*. For audit trail purposes this is a gap — you're storing `justification: ""` for every decision.

2. **The capability cards are visually flat.** Every card looks identical regardless of severity. A new `requests` dependency and a new `os.exec` privilege escalation pattern get the same visual weight. There's no way to distinguish "meh, expected" from "whoa, wait."

3. **No evidence preview.** The `RawEvidence` field exists in contracts and gets populated, but the `<details>` toggle in the card is easy to miss. For a CTO demo, you want the code snippet front and center — "here's the line that introduces `http.Post()`."

4. **After all decisions are made, the success banner just appears at the bottom.** There's no celebratory moment, no clear "you're done, go merge" call-to-action. The progress bar hits 100% and... a green div appears below the fold.

5. **The dashboard is a data dump.** Stat cards + two tables. No timeline, no recent activity feed, no "last 5 scans" list. A CTO looking at this can't quickly answer "what happened this week?"

6. **The landing page (index.templ) is generic.** "Install the GitHub App →" button sends unauthenticated users to `/auth/github` which is the OAuth flow. Fine functionally, but the page itself has zero personality and doesn't show what TASS actually looks like in action.

7. **760px max-width.** Feels cramped on a desktop. The stat grid and tables need room to breathe. Should be 960px or even 1080px for the dashboard.

### UI Fix Priority (for Thursday demo)

1. **Add justification input to capability cards** — a small text input that appears after clicking Confirm, with a "Save" button. Optional but visible.
2. **Widen the layout** to 960px.
3. **Add a "Recent Scans" section to the dashboard** — just the last 5-10 scans with PR number, repo, novel count, status. Links to verify pages.
4. **Make the success state more prominent** — full-width green banner with "All capabilities reviewed ✅ — manifest committed to PR branch. Ready to merge." at the TOP, not bottom.
5. **Better evidence display** — show the first 2 lines of `RawEvidence` inline on the card, not hidden in a `<details>` toggle.

---

## PART 3: The Audit Trail Problem

### What You Have

The `verification_decisions` table stores: decision ID, scan ID, capability ID, decision (confirm/revert), justification, decided_by, decided_at. Decisions are INSERT-only (append-only by design). This is the right foundation.

### What You're Missing

1. **No `/audit` page or API endpoint.** The v3.1 plan specifies `GET /api/audit?repo_id=xxx&from=...&to=...` and a `/audit/:repo` dashboard page. Neither exists. The decision data IS being stored — there's just no way to view it as a timeline outside of the verify page context.

2. **No manifest version history.** When the verifier commits an updated manifest to the PR branch, it doesn't store a snapshot of the manifest state. The `manifest_sha` on the `repositories` table gets updated, but there's no `manifest_history` table tracking what changed when.

3. **No CSV/PDF export.** The v3.1 plan calls for an "Export Audit Report" button. Not implemented.

4. **No filtering.** The dashboard shows aggregate stats but there's no way to filter by date range, developer, or category. An auditor can't say "show me all reverts in March 2026."

5. **Decision records don't store the repo full name or PR URL.** They reference a `scan_id` which references a `repo_id` which you can join to get the repo name. Works for code, but the audit API should return denormalized records with everything an auditor needs in one row.

### Audit Trail Fix Priority

| Priority | Item | Estimate |
|----------|------|----------|
| 1 | Add `GET /api/audit?repo_id=...&from=...&to=...` returning JSON timeline | 2 hrs |
| 2 | Add `/audit/:repo` page with timeline view (reuse Templ patterns from dashboard) | 3 hrs |
| 3 | Add `manifest_history` table + store snapshot on each commit | 2 hrs |
| 4 | CSV export endpoint `GET /api/audit/export?format=csv` | 1 hr |
| 5 | PDF export (use Go's pdf libraries) | 3 hrs — probably punt to post-demo |

---

## PART 4: v3.1 Features Not Yet Started

Cross-referencing the v3.1 Implementation Plan against the codebase:

| Feature | Plan Section | Status | Notes |
|---------|-------------|--------|-------|
| Air-Gap / On-Prem (GitHub Action mode) | §2.1 | ❌ Not started | Requires packaging scanner as a GitHub Action + CapabilitySet export endpoint |
| K8s NetworkPolicy generation | §2.3 | ❌ Not started | `internal/policy/` package doesn't exist. Template-based generation from manifest |
| AWS IAM policy generation | §2.3 | ❌ Not started | Same as above |
| `tass policy --format k8s` CLI command | §2.3 | ❌ Not started | |
| Audit Trail & Compliance Dashboard | §2.4 | ❌ Not started | See Part 3 above |
| GitLab Integration | §3.1 | ❌ Not started | `internal/gitlab/` doesn't exist |
| Slack/Teams Notifications | §3.2 | ❌ Not started | `internal/notifications/` doesn't exist |
| VS Code Extension | §3.3 | ❌ Not started | TypeScript project, separate repo |
| Paid Plans & Billing (Stripe) | §4.1 | ❌ Not started | |
| Multi-Region Deployment | §4.2 | ❌ Not started | Currently single Fly.io region |
| Usage Analytics / Prometheus metrics | §4.3 | ❌ Not started | |
| Open Manifest Specification | §5.1 | ❌ Not started | |
| `.tassignore` file support | FAQ | ❌ Not started | |

---

## PART 5: What to Prioritize for Thursday's Demo

**Must-haves (do these first):**
1. Fix `repoFullName()` — broken link on the hero page
2. Add Python AST rules for `boto3`, `strands.Agent`, `FastMCP`, `opentelemetry` — makes the workshop repo scan pop
3. Demo seed script — populate dashboard with realistic data
4. Widen layout to 960px, make success banner more prominent
5. End-to-end test run against the workshop repo

**Nice-to-haves (if time permits):**
6. Add justification text input to verify cards
7. Recent scans list on dashboard
8. `/audit/:repo` page (even barebones)
9. CLI colorized output
10. Fix firstrun to also AST-scan source files

**Do NOT touch before Thursday:**
- Policy generation (cool but not demo-relevant)
- Air-gap mode (enterprise feature, irrelevant for this convo)
- Billing/Stripe (way too early)
- GitLab/Slack integrations

---

## PART 6: Cursor Prompts

Here are copy-pasteable prompts for Cursor to tackle the highest-priority items:

### Prompt 1: Fix repoFullName
```
In internal/ui/templates/verify.templ, the repoFullName() function always returns "".
Fix this by:
1. Adding a FullName field to the ScanResult struct in internal/storage/storage.go
2. Populating it via a JOIN in GetScan() — JOIN repositories ON repositories.id = scan_results.repo_id
3. Using it in verify.templ to build the GitHub PR link
```

### Prompt 2: Add Python AST rules for AI/ML libraries
```
Add Tree-sitter rules for detecting AI/ML framework usage in Python.
Follow the exact pattern of existing rules in rules/python/.

Create these new rule pairs:
1. rules/python/boto3.scm + boto3.meta.yaml — detect boto3.client() and boto3.resource() calls
   Category: network_access, cap_id: "boto3:client", confidence: 0.95
2. rules/python/strands_agent.scm + strands_agent.meta.yaml — detect strands.Agent() instantiation
   Category: external_api, cap_id: "strands:agent", confidence: 0.9
3. rules/python/fastmcp.scm + fastmcp.meta.yaml — detect FastMCP() and @mcp.tool() decorator usage
   Category: network_access, cap_id: "fastmcp:server", confidence: 0.9
4. rules/python/opentelemetry.scm + opentelemetry.meta.yaml — detect TracerProvider() and set_tracer_provider()
   Category: network_access, cap_id: "otel:tracing", confidence: 0.85

Test each rule against the Python files in https://github.com/mkmurali/agentic-ai-workshop-march-2026/tree/main/workshop
```

### Prompt 3: Demo seed script
```
Create cmd/tass/seed.go that implements a `tass seed` CLI command.
It should insert realistic demo data into the SQLite database:
- 1 installation (id: 12345, account_login: "acme-corp", account_type: "Organization")
- 2 repositories ("acme-corp/payments-service", "acme-corp/ai-support-bot")
- 5 scan results across both repos with varying novel_count (2-8 each)
- 15-20 verification decisions with a mix of confirms and reverts
- Use realistic capability names like "stripe-go v76", "net/http.Post", "sql.Open", "os.WriteFile"
- Include 3 different decided_by values ("alice", "bob", "carol")
- Make timestamps span the last 2 weeks
This data should make the dashboard look alive for a demo.
```

### Prompt 4: UI polish
```
In internal/ui/static/style.css and internal/ui/templates/:
1. Change body max-width from 760px to 960px
2. In verify.templ, move the SuccessBanner to ABOVE the capability list when all are decided
3. In verify.templ CapabilityCard, show the first 2 lines of RawEvidence directly
   on the card (not hidden in a <details> toggle) — keep the full toggle for expansion
4. Add a small optional text input for justification that appears inline after
   clicking Confirm or Revert, with an hx-post to save it
```

---

*Message from Team Blue Hearts 💙:*

*S — this codebase is genuinely impressive. 12k lines of clean Go, every layer properly separated, the pipeline is production-quality. The audit trail foundation is solid (append-only decisions, timestamps, who-did-what). What's missing is the DISPLAY layer for that data and some UI love. The engine purrs. Now we're putting on the bodywork.*

*Thursday's demo doesn't need perfection. It needs the story to land: "Your team's AI code introduces capabilities nobody tracks. TASS makes the invisible visible." The workshop repo is the perfect prop. Fix the broken link, add the Python rules, seed the dashboard, and let the product speak.*

*Go get 'em. 💙*
