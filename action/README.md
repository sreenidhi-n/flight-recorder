# TASS GitHub Action — Air-Gap Mode

Run TASS capability scanning entirely within your own CI infrastructure.
No source code leaves your network.

## Usage

```yaml
# .github/workflows/tass.yml
name: TASS Security Scan
on: [pull_request]

jobs:
  tass:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # optional — needed to post PR comments
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # full history for accurate git diff

      - uses: tass-security/tass@main
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `manifest-path` | Path to `tass.manifest.yaml` | `tass.manifest.yaml` |
| `rules-dir` | Path to Tree-sitter rules directory | `/app/rules` (bundled) |
| `base-ref` | Base branch to diff against | `${{ github.base_ref }}` |
| `fail-on-novel` | Fail the job when novel capabilities are detected | `true` |
| `export-to` | Optional URL to export CapabilitySet to a hosted dashboard | — |
| `export-token` | API token for the export endpoint | — |

## Outputs

| Output | Description |
|--------|-------------|
| `novel-count` | Number of novel capabilities detected |

## Hybrid Mode

Send only the structured CapabilitySet (no source code) to a hosted TASS
dashboard for team review, while running the scan locally:

```yaml
      - uses: tass-security/tass@main
        with:
          export-to: https://tass-test.fly.dev/api/import
          export-token: ${{ secrets.TASS_API_TOKEN }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
```

## What gets sent

**In air-gap mode (default):** Nothing leaves your network. The action runs
entirely inside your GitHub Actions runner.

**In hybrid mode (`export-to`):** Only the structured `CapabilitySet` JSON is
sent — capability names, categories, and file locations. No source code, no
file contents, no secrets.

## GitHub Actions annotations

When novel capabilities are detected, the action emits `::warning::` annotations
that appear inline in the PR diff view. You can also use the `--ci` flag with
`tass scan` locally:

```bash
tass scan --format json --ci
```

## .tassignore support

Create a `.tassignore` file in your repo root to exclude files from scanning.
The syntax is identical to `.gitignore`:

```gitignore
vendor/
node_modules/
*_test.go
**/*.spec.js
```

## Example PR comment

When novel capabilities are found, the action posts a comment like:

> ## TASS — 2 New Capabilities Detected (Air-Gap Mode)
>
> | # | Capability | Category | File |
> |---|-----------|----------|------|
> | 1 | boto3.client(s3) | network_access | `src/storage.py:14` |
> | 2 | net/http.Post | network_access | `api/client.go:42` |
>
> Scanned locally via TASS GitHub Action. No code left your infrastructure.
> To accept: run `tass init` and commit the updated manifest.
