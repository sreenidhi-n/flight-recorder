# TASS Installation Guide & Walkthrough

This guide walks through installing the TASS GitHub App on your organization, understanding the initial setup flow, and what to expect on your first pull request scan.

---

## Prerequisites

- A GitHub organization or personal account with at least one repository
- Permission to install GitHub Apps on your organization (org owner or sufficient permissions)
- No local tools to install — TASS is a hosted GitHub App

---

## Part 1: Installing the GitHub App

### Step 1: Navigate to the App

Go to the TASS GitHub App page:
- **Hosted:** `https://github.com/apps/tass-security`
- **Self-hosted:** Your Fly.io URL (e.g., `https://app.tass.dev`)

### Step 2: Click Install

Click the green **Install** button.

### Step 3: Choose Repositories

GitHub will ask which repositories TASS should have access to:
- **All repositories** — TASS scans every repo in the org (recommended for visibility)
- **Select repositories** — choose specific repos for a targeted rollout

> **Tip:** Start with 2–3 active repos. You can always add more later from the GitHub App settings.

### Step 4: Authorize

Review the permissions TASS requests:
- `Read` — repository contents (to fetch files for scanning)
- `Read & Write` — checks (to post pass/fail status on PRs)
- `Read & Write` — pull requests (to post PR comments)
- `Read & Write` — contents (to commit `tass.manifest.yaml` to PR branches)

Click **Install & Authorize**.

---

## Part 2: The First-Run Flow (What Happens Automatically)

Immediately after installation, TASS runs in the background for each selected repository:

1. **Scans the default branch** — TASS fetches dependency files (`go.mod`, `requirements.txt`, `package.json`) and source files from your `main`/`master` branch.
2. **Generates a baseline manifest** — All detected capabilities are written to `tass.manifest.yaml`.
3. **Opens a setup PR** — TASS opens a pull request titled `chore: add initial TASS behavioral manifest` on each repository.

You will receive GitHub notifications about these PRs.

### Example Setup PR

```
Title: chore: add initial TASS behavioral manifest
Branch: tass/initial-manifest → main

This PR adds the initial TASS behavioral manifest for this repository.
TASS detected 7 existing capabilities in your codebase...
```

### Review the Setup PR

1. Open the PR and review `tass.manifest.yaml`
2. Verify the listed capabilities look correct for your codebase
3. If a capability shouldn't be there, remove it before merging (TASS won't flag it once it's in the manifest)
4. **Merge the PR** to activate scanning on future PRs

---

## Part 3: Your First Scan (Developer Walkthrough)

After the manifest PR is merged, every new PR on the repo is automatically scanned.

### Scenario: Adding a new dependency

Alice opens a PR that adds the Stripe SDK:

```
git checkout -b feat/payment-processing
echo "stripe==6.0.0" >> requirements.txt
git push origin feat/payment-processing
# Open pull request on GitHub
```

### What TASS does automatically (within ~30 seconds)

1. **Receives the webhook** from GitHub
2. **Fetches the changed files** via GitHub API (no git clone)
3. **Scans for new capabilities** by diffing the PR against the base branch manifest
4. **Posts a PR comment:**

```markdown
## 🔍 TASS — 1 New Capability Detected

| # | Capability | Category | Detected In | Layer |
|---|-----------|----------|-------------|-------|
| 1 | stripe 6.0.0 | 📦 Dependency | requirements.txt | Dep Diff |

**→ [Review & Verify on TASS](https://app.tass.dev/verify/scan-abc123)**

<!-- tass-scan:abc123 -->
```

5. **Creates a GitHub Check** — the PR check is `action_required` (blocks merge if branch protection is enabled)

### What Alice does

1. Sees the TASS comment in her PR
2. Clicks **"Review & Verify on TASS"**
3. **Signs in with GitHub** (first time only — seamless OAuth flow)
4. Lands on the verification page:

```
PR #42: "Add payment processing"
1 of 1 reviewed

┌─────────────────────────────────┐
│ 📦 NEW DEPENDENCY               │
│ stripe 6.0.0                    │
│ Detected in: requirements.txt   │
│                                 │
│ [✅ Confirm]  [↩️ Revert]      │
└─────────────────────────────────┘
```

5. Clicks **✅ Confirm** (this was intentional — adding Stripe for payment processing)

### What TASS does after the decision

1. Records the decision (Alice, confirmed, stripe 6.0.0)
2. Commits the updated `tass.manifest.yaml` to Alice's PR branch
3. Updates the GitHub Check → **✅ success**
4. Updates the PR comment → "All capabilities verified ✅"

**The PR is now ready to merge.** Alice didn't touch her terminal once for the TASS part.

---

## Part 4: Revert Flow (Unintended Capability)

Bob opens a PR and TASS flags an unexpected capability:

```
## 🔍 TASS — 1 New Capability Detected

| # | Capability | Category | Detected In |
|---|-----------|----------|-------------|
| 1 | os.WriteFile | 📁 Filesystem | internal/util.go:88 |
```

Bob didn't intend to add filesystem writes. He clicks **↩️ Revert**.

- The GitHub Check stays at `action_required` (the code change needs to be removed)
- A note is added to the PR discussion
- Bob removes the unintended code and pushes a new commit — TASS rescans automatically

---

## Part 5: The Dashboard

Visit `https://app.tass.dev/dashboard` (or your self-hosted URL + `/dashboard`) to see:

- Total scans across all repos
- Per-developer override rates
- Category breakdown (which types of capabilities get reverted most?)
- Recent activity feed

The dashboard helps security leads answer: *"Are developers actually reviewing capabilities, or rubber-stamping everything?"*

---

## FAQ

**Q: Does TASS store our source code?**
A: No. TASS processes source code in-memory during scanning, then immediately discards it. Only the structured capability list (what your code can do, not the code itself) is stored in the database.

**Q: What if the manifest PR gets merge conflicts?**
A: TASS handles this gracefully — it fetches the latest file SHA before committing to avoid conflicts.

**Q: What about fork PRs?**
A: GitHub restricts write access on fork PRs. TASS will post a PR comment but cannot create a check run. This is a GitHub limitation, not a TASS bug.

**Q: Can I exclude files or directories from scanning?**
A: Not in v3.0. Coming in v3.1: a `.tassignore` file (same syntax as `.gitignore`).

**Q: What happens if TASS goes down?**
A: Webhooks are queued by GitHub and retried. The TASS check on the PR will stay pending until the scan completes. No PR is permanently blocked.

**Q: How do I remove TASS from a repo?**
A: Go to GitHub Settings → Integrations → GitHub Apps → Configure TASS → remove the repository. The manifest stays in the repo (it's just a YAML file) and can be removed manually if desired.
