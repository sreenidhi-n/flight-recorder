# TASS v3.1+ Implementation Roadmap
## Post-MVP Feature Plan: "From Working to Winning"

> **Context:** v3.0 is built. Core detection engine, GitHub App webhooks, verification UI, manifest diffing — all operational. This roadmap covers everything that comes next, organized by strategic priority and with enough implementation detail that you can confidently answer "yes, and here's how" in any pitch conversation.
>
> — Team Blue Hearts 💙, Principal Architect

---

## Roadmap at a Glance

| Wave | Theme | Timeline | Key Deliverables |
|------|-------|----------|-----------------|
| **Wave 1** | Harden & Demo | Week 1-2 | Stable hosting, bug fixes, polish for live demos |
| **Wave 2** | Enterprise Readiness | Week 3-6 | Air-gap mode, CLI tool, policy generation, audit trail |
| **Wave 3** | Platform Expansion | Week 7-10 | GitLab support, Slack/Teams notifications, VS Code extension |
| **Wave 4** | Monetization & Scale | Week 11-14 | Paid plans, billing, multi-region, usage analytics |
| **Wave 5** | Ecosystem & Moat | Week 15+ | Open manifest spec, partner integrations, Capability Graph |

---

## Wave 1: Harden & Demo (Week 1-2)
### *"Make it demoable. Make it reliable. Make it not 404 on the homepage."*

These are the things you fix BEFORE showing anyone.

---

### 1.1 — Root Route & Navigation Polish
**⏱ ~2 hours**

- Add `/` → redirect to `/dashboard`
- Add a proper landing page at `/welcome` for unauthenticated users (explains what TASS is, "Login with GitHub" button)
- Ensure all navigation links work: dashboard → verify → back to dashboard
- 404 page should be branded, not the default Go 404

**Tell Claude Code:**
```
Add a root route handler that redirects authenticated users to /dashboard
and unauthenticated users to /welcome. Create a simple welcome.templ page
with the TASS logo, a one-line description, and a "Login with GitHub" button
that goes to /auth/github. Add a branded 404 page.
```

---

### 1.2 — Stable Hosting Setup
**⏱ ~3 hours**

**Option A: Named Cloudflare Tunnel (free, stable URL)**
- Install `cloudflared` and create a named tunnel (not the quick `--url` mode)
- Configure a fixed subdomain: `tass-demo.yourdomain.com` or use a free `.cfargotunnel.com` address
- Auto-start via `cloudflared service install` so it survives laptop restarts
- Update GitHub App webhook URL once, never again

**Option B: Railway/Render ($5-7/month)**
- Docker deploy, persistent volume for SQLite
- Fixed URL, always-on, no laptop dependency

For the pitch tomorrow: Option A is fine. You're demo-ing from your laptop anyway.

---

### 1.3 — PR Scanning Bug Fix
**⏱ ~2-4 hours**

Debug the webhook → scan → comment pipeline. The chain is:
1. GitHub sends `pull_request` event to `/webhooks/github`
2. Webhook handler verifies signature, parses event
3. Handler fetches changed files via GitHub API
4. Scanner runs on fetched files
5. Results diffed against manifest
6. PR comment + Check created

Add logging at each step if not already present. The bug is in one of these handoffs.

**Tell Claude Code:**
```
Add structured slog.Info logging at every step of the webhook → scan → comment
pipeline. Log: webhook received (event type, repo, PR number), files fetched
(count, names), scan results (capabilities found), diff results (novel count),
and comment/check creation (success/failure with GitHub API response).
Then trigger a real PR and paste me the logs.
```

---

### 1.4 — Demo Polish
**⏱ ~2 hours**

- Seed the database with realistic-looking demo data (a few past scans, some confirm/revert decisions) so the dashboard doesn't look empty
- Ensure the verification UI looks good on a projector/screen share (test at 1920x1080)
- Test the full flow end-to-end: install app → open PR → see comment → click link → verify → check goes green

---

## Wave 2: Enterprise Readiness (Week 3-6)
### *"The features that make a CTO say 'yes, we can deploy this.'"*

---

### 2.1 — Air-Gap / On-Prem Mode (Hybrid Architecture)
**⏱ ~1.5 weeks** | **Trigger: Defense/fintech/regulated prospect**

This is the "Zero Exfiltration Architecture" from your pitch deck. Here's exactly how it works:

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│  CUSTOMER'S INFRASTRUCTURE (their GitHub Actions runner)     │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  TASS Scanner (GitHub Action)                         │   │
│  │  - Runs as a step in their CI/CD pipeline             │   │
│  │  - Scans code LOCALLY — never leaves their network    │   │
│  │  - Produces a CapabilitySet (structured JSON output)  │   │
│  │  - Diffs against manifest locally                     │   │
│  │  - Posts PR comment directly (using their GITHUB_TOKEN)│  │
│  └────────────────────┬─────────────────────────────────┘   │
│                       │ (optional)                           │
│                       ▼                                      │
│           Structured CapabilitySet JSON                      │
│           (NO source code — just capability metadata)        │
└───────────────────────┼─────────────────────────────────────┘
                        │ (optional, customer-controlled)
                        ▼
              ┌─────────────────────┐
              │  TASS Cloud Dashboard│
              │  (your hosted app)   │
              │  - Aggregated metrics│
              │  - Override tracking │
              │  - Team dashboard    │
              └─────────────────────┘
```

**Implementation Steps:**

1. **Package scanner as GitHub Action** (~3 days)
   - Create `action.yml` + Dockerfile
   - The Action runs the TASS binary with `tass scan --base $GITHUB_BASE_REF --format json`
   - Action posts PR comment using the built-in `GITHUB_TOKEN` (no external service needed)
   - Action creates GitHub Check directly
   - This runs entirely in the customer's CI — no data leaves their infra

2. **CapabilitySet export endpoint** (~1 day)
   - `tass scan --export-to https://app.tass.dev/api/import --token <api-key>`
   - Sends ONLY the structured CapabilitySet (capability names, categories, decisions)
   - NEVER sends source code, file contents, or raw evidence
   - Customer can audit exactly what's sent (it's JSON, they can intercept it)

3. **Fully air-gapped mode** (~1 day)
   - `tass scan` + `tass serve` both run locally
   - Verification UI served on `localhost:8080`
   - SQLite database stays on their machine
   - Zero network calls except to GitHub API (which they already trust)
   - Perfect for air-gapped/classified environments

**What to say in the pitch:**
> "TASS has two deployment modes. Our hosted platform gives you zero-install GitHub App integration. For environments where code can't leave your network, we ship the same scanner as a GitHub Action that runs entirely in your CI. Only structured metadata — never source code — optionally syncs to our dashboard. Fully air-gapped mode is also available where nothing leaves your infrastructure at all."

---

### 2.2 — CLI Tool
**⏱ ~1 week** | **Trigger: Non-GitHub users, power users, enterprise**

The scanner already exists. The CLI is a thin wrapper.

**Commands:**
```bash
tass init                    # Full repo scan → generate tass.manifest.yaml
tass scan --base main        # Diff scan → list novel capabilities
tass scan --format json      # Machine-readable output for CI pipelines
tass serve                   # Start local verification UI + dashboard
tass verify --scan <id>      # Open verification UI for specific scan
tass export                  # Export manifest as SBOM (CycloneDX format)
tass version                 # Version info
```

**Distribution:**
- `brew install tass-security/tap/tass` (Homebrew tap)
- `curl -fsSL https://tass.dev/install.sh | sh` (shell script)
- GitHub Releases (pre-built binaries for macOS arm64/amd64, Linux amd64)
- `go install github.com/tass-security/tass@latest` (for Go devs)

**Implementation:**
- Already have `cmd/tass/main.go` with `init`, `scan`, `serve`
- Add `verify` and `export` subcommands
- Add `goreleaser` config for cross-platform binary builds
- Create Homebrew tap repository
- Write install script that detects OS/arch and downloads correct binary

---

### 2.3 — Policy Generation (Kubernetes NetworkPolicy)
**⏱ ~1 week** | **Trigger: Platform engineering / infrastructure teams**

The manifest already contains what the code CAN do. Policy generation translates that into what it SHOULD be ALLOWED to do.

**How it works:**
```
tass.manifest.yaml                    Generated NetworkPolicy
─────────────────────                 ──────────────────────────
capabilities:                         apiVersion: networking.k8s.io/v1
  - name: stripe-api                  kind: NetworkPolicy
    category: external_api            metadata:
    endpoints:                          name: myapp-netpol
      - api.stripe.com               spec:
  - name: postgres-write                podSelector:
    category: database_operation          matchLabels:
    endpoints:                              app: myapp
      - postgres.internal:5432          egress:
  - name: s3-upload                     - to:
    category: network_access              - ipBlock: {cidr: api.stripe.com/32}
    endpoints:                            ports: [{port: 443}]
      - s3.amazonaws.com               - to:
                                          - podSelector: {matchLabels: {app: postgres}}
                                          ports: [{port: 5432}]
                                        - to:
                                          - ipBlock: {cidr: s3.amazonaws.com/32}
                                          ports: [{port: 443}]
```

**Implementation:**
```go
// internal/policy/k8s.go
func GenerateNetworkPolicy(m *manifest.Manifest, opts PolicyOpts) ([]byte, error)

// internal/policy/iam.go (Wave 2 stretch goal)
func GenerateIAMPolicy(m *manifest.Manifest, opts PolicyOpts) ([]byte, error)
```

- Template-based generation using Go's `text/template`
- Output: YAML for K8s NetworkPolicy, JSON for AWS IAM
- New CLI command: `tass policy --format k8s` / `tass policy --format iam`
- New API endpoint: `GET /api/policy?repo_id=xxx&format=k8s`
- New dashboard section: "Generated Policies" tab with copy-to-clipboard

**What to say in the pitch:**
> "The manifest doesn't just track capabilities — it generates infrastructure policies. If your code only talks to Stripe and Postgres, TASS generates a Kubernetes NetworkPolicy that blocks everything else. Your infrastructure security stays in sync with your code, automatically."

---

### 2.4 — Audit Trail & Compliance Dashboard
**⏱ ~4 days** | **Trigger: SOC2/compliance conversations**

Everything you need for a compliance auditor to look at and say "yes, this is sufficient evidence of capability review."

**What it includes:**
- Complete decision history: who confirmed/reverted what, when, with what justification
- Manifest version history: every change to the manifest, with diff view
- Export to CSV/PDF for audit evidence packages
- Tamper-evident: decisions are append-only in SQLite (never updated, never deleted)
- API endpoint: `GET /api/audit?repo_id=xxx&from=2026-01-01&to=2026-06-30`

**New dashboard page: `/audit/:repo`**
- Timeline view of all capability decisions
- Filter by developer, category, decision type
- "Export Audit Report" button → generates PDF

---

## Wave 3: Platform Expansion (Week 7-10)
### *"Go where the developers are."*

---

### 3.1 — GitLab Integration
**⏱ ~1 week** | **Trigger: Design partner uses GitLab**

GitLab has a similar webhook model to GitHub but with different APIs.

**Implementation:**
- `internal/gitlab/` package — mirrors `internal/github/`
- GitLab webhook events: `merge_request` (equivalent to `pull_request`)
- GitLab API: same pattern — fetch files, post comments, create pipeline status
- Auth: GitLab access token (simpler than GitHub App JWT)
- MR comments use GitLab's Markdown (very similar to GitHub's)

**The scanner doesn't change at all.** It already works on `[]byte`. Only the integration layer is new.

---

### 3.2 — Slack / Microsoft Teams Notifications
**⏱ ~3 days** | **Trigger: Security teams want alerts**

**Notify on:**
- New capabilities detected (summary after scan)
- Capabilities reverted (someone said "no, we didn't intend this")
- High override rate warning (>50% confirm rate for a developer)
- Weekly digest: capabilities added across all repos

**Implementation:**
- Slack: Incoming Webhook URL (customer provides, we POST to it)
- Teams: same pattern, different payload format
- Settings page in dashboard: paste webhook URL, select notification types
- `internal/notifications/slack.go` and `internal/notifications/teams.go`
- Fire-and-forget: if notification fails, log and continue (don't block the scan)

---

### 3.3 — VS Code Extension
**⏱ ~1 week** | **Trigger: Developer experience differentiation**

Lightweight extension that reads `tass.manifest.yaml` and shows capability information inline.

**Features:**
- Gutter icons next to lines that introduce capabilities (e.g., `http.Post()`)
- Hover tooltip: "This line introduces network_access. Capability is [declared/undeclared] in manifest."
- Command palette: "TASS: Show Manifest Summary" → sidebar panel listing all declared capabilities
- Status bar: "TASS: 14 capabilities declared" with link to manifest

**Implementation:**
- TypeScript extension (yes, this is the ONE thing not in Go — VS Code extensions must be JS/TS)
- Reads `tass.manifest.yaml` from workspace root
- Optionally runs `tass scan --format json` and displays results
- No network calls — everything local
- Publish to VS Code Marketplace (free)

---

## Wave 4: Monetization & Scale (Week 11-14)
### *"Turn users into customers."*

---

### 4.1 — Paid Plans & Billing
**⏱ ~1 week**

**Plan structure:**
```
Free:       1 repo, 50 scans/month, 1 user
Team:       10 repos, unlimited scans, 10 users, $15/user/month
Enterprise: Unlimited repos, unlimited scans, unlimited users,
            SSO, audit export, policy generation, on-prem mode,
            $40/user/month (annual contract)
```

**Implementation:**
- Stripe Checkout for subscription management
- `internal/billing/stripe.go` — webhook handler for subscription events
- Plan gating middleware: check plan limits before processing webhook scans
- Free tier: no credit card required (acquisition funnel)
- Dashboard: billing page with current plan, usage, upgrade button

---

### 4.2 — Multi-Region Deployment
**⏱ ~3 days**

- Deploy to multiple Fly.io regions (or Railway/Render regions)
- EU region for GDPR-sensitive customers (Frankfurt)
- US region for US customers (Virginia)
- DNS-based routing via Cloudflare (geo-aware)
- SQLite per region (eventually migrate to Turso for distributed SQLite or PostgreSQL)

---

### 4.3 — Usage Analytics & Internal Metrics
**⏱ ~3 days**

- Track: scans/day, capabilities detected/day, verify latency, scan duration
- Prometheus metrics endpoint: `/metrics`
- Grafana dashboard (or simple internal dashboard page)
- Alert on: scan failures, webhook delivery failures, high error rates
- This is for YOUR operational awareness, not customer-facing

---

## Wave 5: Ecosystem & Moat (Week 15+)
### *"Make TASS the standard, not just a tool."*

---

### 5.1 — Open Manifest Specification
**⏱ ~2 weeks**

- Publish `tass.manifest.yaml` spec as an open standard
- GitHub repo: `tass-security/manifest-spec`
- JSON Schema for validation
- Spec document with versioning, field definitions, examples
- Submit to OpenSSF or OWASP for consideration
- Blog post: "Introducing the Behavioral SBOM Specification"

**Why this matters:** If other tools read/write manifest files, TASS becomes the standard. Standards are nearly impossible to displace.

---

### 5.2 — SAST/SCA Vendor Integrations
**⏱ ~1 week per integration**

- **Snyk integration:** Enrich Snyk findings with manifest behavioral context
  - "This CVE is in a module that has network_access capability" → higher severity
  - Implementation: Snyk webhook → match against TASS manifest → annotate
  
- **Semgrep integration:** Custom Semgrep rules that reference the manifest
  - "Flag any http.Post() call in a module not declared with network_access"
  - Implementation: Semgrep rule templates generated from manifest

---

### 5.3 — Capability Graph (Cross-Customer Intelligence)
**⏱ ~3 weeks** | **Trigger: 500+ repos using manifests**

Anonymized, aggregated capability data across all TASS customers.

**What it enables:**
- "This capability pattern has never been seen across any TASS customer" → higher risk signal
- "87% of repos that use stripe-go also declare database_write" → expected pattern
- Anomaly detection: "This repo added 15 new capabilities in one PR — that's unusual"

**Implementation:**
- Anonymized CapabilitySet export (strip repo names, file paths, developer names)
- Aggregate statistics stored separately from customer data
- API: `GET /api/intelligence?capability=network_access` → prevalence, common co-occurrences
- Dashboard widget: "Risk score: 7/10 — this capability pattern is unusual"

---

### 5.4 — AI Code Gen Tool Integration (The Home Run)
**⏱ ~2 weeks** | **Trigger: Partnership conversation with Cursor/Copilot/Cody**

The manifest as a constraint file for AI code generation.

**How it works:**
- AI coding tool reads `tass.manifest.yaml` before generating code
- If the manifest doesn't declare `network_access`, the AI avoids generating `http.Post()`
- If a developer asks "add a payment form" and the manifest doesn't include Stripe, the AI warns: "This would require adding stripe-go, which is not in your capability manifest. Proceed?"

**Implementation (on TASS's side):**
- Publish manifest as a well-documented, machine-readable format (done in 5.1)
- Create a reference prompt/system-message for AI tools that explains how to read the manifest
- Build a demo with Cursor's custom rules feature (`.cursorrules` file that references the manifest)
- This is mostly a partnerships + documentation play, not heavy engineering

**What to say in the pitch:**
> "Long term, we want AI coding tools to read the manifest BEFORE generating code. Instead of catching unapproved capabilities after the fact, the AI never generates them in the first place. We're in conversations about this with [don't name specific companies unless you actually are]."

---

## Feature FAQ: Quick Answers for the Pitch

**"Can this run on-prem?"**
> Yes. Same binary, two modes. Hosted GitHub App for zero-friction, or GitHub Action running entirely in your CI for air-gapped environments. Only structured metadata — never source code — optionally syncs to our dashboard.

**"Does it work with GitLab?"**
> GitLab support is in our near-term roadmap. The scanner is platform-agnostic — it works on any code. The integration layer for GitLab webhooks and merge request comments is a straightforward build.

**"What about false positives?"**
> The manifest is declarative, not inferred. A capability is either in the manifest or it isn't — it's a deterministic string comparison, not a probabilistic guess. False positive rate against the declared baseline is effectively zero. Detection layer coverage improves over time, but missed capabilities are false negatives (additive misses), not false positives.

**"How does this compare to Snyk / Semgrep?"**
> Different category. Snyk finds vulnerabilities — code that's broken. TASS finds capabilities — code that works but does more than intended. We complement SAST/SCA tools, we don't compete with them. Actually, we make their findings more actionable by adding behavioral context.

**"What if developers just click Confirm on everything?"**
> We track override rates per developer. If someone confirms >50% of flagged capabilities, the dashboard flags it. The audit trail shows exactly who approved what. Social pressure + visibility is the mechanism — same as code review approval rates.

**"Can it generate infrastructure policies?"**
> Yes. The manifest contains exactly which external services, databases, and network endpoints the code uses. We generate Kubernetes NetworkPolicies and AWS IAM policies that restrict access to only what's declared. Your infrastructure security stays in sync with your code.

**"What's your pricing model?"**
> Free tier for individual repos. Team plan at $15/user/month. Enterprise with on-prem deployment, SSO, and audit exports at $40/user/month. We're currently in design partner mode — free access in exchange for feedback.

**"What's your competitive moat?"**
> Four layers: (1) The manifest format — if it becomes the standard, we're the reference implementation. (2) Committed manifests create switching costs — they accumulate institutional knowledge. (3) Policy generation puts us in a position GitHub can't easily clone — that crosses organizational boundaries. (4) Long-term, the cross-customer Capability Graph creates network effects.

---

## The Pitch Timeline Visual

```
         NOW          3 months        6 months        12 months
          │               │               │               │
  v3.0 ──▶│◄── Wave 1-2 ──▶│◄── Wave 3-4 ──▶│◄── Wave 5 ───▶│
          │               │               │               │
  MVP     │  Enterprise   │  Platform     │  Ecosystem    │
  Working │  Ready        │  Expansion    │  & Standard   │
          │               │               │               │
  • GitHub App            │               │               │
  • Scan + Verify         │               │               │
  • Dashboard    • Air-gap mode  • GitLab        • Open spec
  • Manifest     • CLI tool      • Slack/Teams   • SAST integrations
                 • K8s policies  • VS Code       • Capability Graph
                 • Audit trail   • Paid plans    • AI tool integration
```

---

*"You don't need every feature built to sell the vision. You need every feature planned well enough that when someone asks 'can you do X?' you say 'yes, here's exactly how, and here's when.' That's what this document is for."*

— Team Blue Hearts 💙, Principal Architect
