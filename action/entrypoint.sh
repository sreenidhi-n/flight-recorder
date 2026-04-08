#!/bin/bash
set -e

MANIFEST="${MANIFEST_PATH:-tass.manifest.yaml}"
RULES="${RULES_DIR:-/app/rules}"
BASE="${BASE_REF:-main}"
FAIL_ON_NOVEL="${FAIL_ON_NOVEL:-true}"

echo "::group::TASS Security Scan"
echo "Scanning against base: $BASE"
echo "Manifest: $MANIFEST"
echo "Rules dir: $RULES"

# Run scan in JSON + CI mode so we get annotations and structured output.
RESULT=$(tass scan \
  --path . \
  --base "$BASE" \
  --rules-dir "$RULES" \
  --format json \
  --ci 2>/tmp/tass-stderr.txt) || SCAN_EXIT=$?

SCAN_EXIT="${SCAN_EXIT:-0}"

# Capture any stderr annotations (::warning:: etc.) already emitted by tass.
if [ -s /tmp/tass-stderr.txt ]; then
  cat /tmp/tass-stderr.txt
fi

# Parse novel count from JSON output. tass scan --format json returns [] for
# zero novel caps or a JSON array for non-zero.
NOVEL_COUNT=$(echo "$RESULT" | jq '. | if type == "array" then length else 0 end' 2>/dev/null || echo "0")

# Output step summary to GitHub Actions job summary.
{
  echo "## TASS Security Scan Results"
  echo ""
  if [ "$NOVEL_COUNT" = "0" ]; then
    echo "✅ **No novel capabilities detected.** All capabilities are in the manifest."
  else
    echo "⚠️ **$NOVEL_COUNT novel capability(s) detected** that are not in \`$MANIFEST\`."
    echo ""
    echo "| # | Capability | Category | File |"
    echo "|---|-----------|----------|------|"
    echo "$RESULT" | jq -r 'to_entries[] | "| \(.key+1) | \(.value.name) | \(.value.category) | `\(.value.location.file // "unknown"):\(.value.location.line // 0)` |"' 2>/dev/null || true
    echo ""
    echo "> Scanned locally via TASS GitHub Action. No code left your infrastructure."
    echo ""
    echo "**To resolve:** run \`tass init\` to accept these as your new baseline, or revert the changes that introduced these capabilities."
  fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

# Post PR comment if GITHUB_TOKEN and PR_NUMBER are available.
if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$PR_NUMBER" ] && [ "$NOVEL_COUNT" != "0" ]; then
  echo "Posting PR comment..."

  TABLE=$(echo "$RESULT" | jq -r '[
    "| # | Capability | Category | File |",
    "|---|-----------|----------|------|"
  ] + (to_entries | map("| \(.key+1) | \(.value.name) | \(.value.category) | `\(.value.location.file // "unknown"):\(.value.location.line // 0)` |")) | join("\n")' 2>/dev/null || echo "")

  BODY="## TASS — $NOVEL_COUNT New Capability Detected (Air-Gap Mode)\n\n${TABLE}\n\n> Scanned locally via TASS GitHub Action. No code left your infrastructure.\n> To accept: run \`tass init\` and commit the updated manifest."

  curl -s -X POST \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" \
    -d "$(jq -n --arg body "$(printf '%b' "$BODY")" '{body: $body}')" \
    > /dev/null
fi

# Export to hosted dashboard if configured (hybrid mode).
# Only the CapabilitySet (no source code) is sent.
if [ -n "$EXPORT_TO" ] && [ -n "$RESULT" ] && [ "$RESULT" != "[]" ]; then
  echo "Exporting CapabilitySet to $EXPORT_TO..."
  curl -s -X POST \
    -H "Content-Type: application/json" \
    ${EXPORT_TOKEN:+-H "Authorization: Bearer $EXPORT_TOKEN"} \
    "$EXPORT_TO" \
    -d "$RESULT" \
    > /dev/null || echo "::warning::TASS: export to $EXPORT_TO failed (non-fatal)"
fi

echo "novel_count=$NOVEL_COUNT" >> "${GITHUB_OUTPUT:-/dev/null}"

echo "::endgroup::"

# Fail the check if novel capabilities were found and fail-on-novel is true.
if [ "$NOVEL_COUNT" != "0" ] && [ "$FAIL_ON_NOVEL" = "true" ]; then
  exit 1
fi

exit 0
