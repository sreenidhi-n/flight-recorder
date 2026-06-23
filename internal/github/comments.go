package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/tass-security/tass/internal/contract"
	"github.com/tass-security/tass/pkg/contracts"
)

// tassMarkerPrefix is an HTML comment embedded in every TASS PR comment.
// Used to find and update existing comments instead of creating duplicates.
const tassMarkerPrefix = "<!-- tass-scan-id:"

// CreateOrUpdateComment posts a PR comment, or updates the existing TASS comment
// on the same PR if one already exists (identified by the hidden marker).
// Returns the comment ID.
func (a *App) CreateOrUpdateComment(ctx context.Context, token, owner, repo string, prNumber int, body string) (int64, error) {
	// Search for an existing TASS comment on this PR
	existingID, err := a.findTASSComment(ctx, token, owner, repo, prNumber)
	if err != nil {
		return 0, fmt.Errorf("find existing comment: %w", err)
	}

	if existingID != 0 {
		// Update existing comment
		url := fmt.Sprintf("%s/repos/%s/%s/issues/comments/%d",
			a.base(), owner, repo, existingID)
		if _, err := a.apiPatch(ctx, token, url, map[string]any{"body": body}); err != nil {
			return 0, fmt.Errorf("update comment %d: %w", existingID, err)
		}
		return existingID, nil
	}

	// Create new comment
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments",
		a.base(), owner, repo, prNumber)
	respBody, err := a.apiPost(ctx, token, url, map[string]any{"body": body})
	if err != nil {
		return 0, fmt.Errorf("create comment: %w", err)
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("parse comment response: %w", err)
	}
	return result.ID, nil
}

// findTASSComment searches the first page of PR comments for one containing
// the TASS marker prefix. Returns 0 if not found.
func (a *App) findTASSComment(ctx context.Context, token, owner, repo string, prNumber int) (int64, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=100",
		a.base(), owner, repo, prNumber)

	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := a.apiGet(ctx, token, url, &comments); err != nil {
		return 0, fmt.Errorf("list comments: %w", err)
	}

	for _, c := range comments {
		if strings.Contains(c.Body, tassMarkerPrefix) {
			return c.ID, nil
		}
	}
	return 0, nil
}

// RenderComment builds the Markdown body for a PR comment.
// violations are contract hard-blocks rendered above the regular capability table.
// An optional AISignal may be passed as the last argument; when IsAIGenerated is
// true a warning badge is injected at the top of the comment.
func RenderComment(scanID string, novelCaps []contracts.Capability, violations []contract.Violation, baseURL string, ai ...AISignal) string {
	var b strings.Builder

	// --- AI-generated code badge (injected first, before all other sections) ---
	var aiSig AISignal
	if len(ai) > 0 {
		aiSig = ai[0]
	}
	if aiSig.IsAIGenerated {
		fmt.Fprintf(&b, "> 🤖 **AI-Generated Code Detected: Stricter capability review applied.**\n")
		if len(aiSig.Signals) > 0 {
			for _, s := range aiSig.Signals {
				fmt.Fprintf(&b, "> - %s\n", s)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	// --- Contract violations section (hard blocks) ---
	if len(violations) > 0 {
		fmt.Fprintf(&b, "## 🚫 TASS — Contract Violations\n\n")
		fmt.Fprintf(&b, "> **These capabilities are hard-blocked by `tass.contract.yaml`.**\n")
		fmt.Fprintf(&b, "> They cannot be resolved via `/tass confirm`. Edit `tass.contract.yaml` to allow them, or remove the offending code.\n\n")

		fmt.Fprintf(&b, "| Rule | Capability | Reason |\n")
		fmt.Fprintf(&b, "|------|------------|--------|\n")
		for _, v := range violations {
			capName := v.Reason
			if v.Capability.Name != "" {
				capName = v.Capability.Name
			}
			fmt.Fprintf(&b, "| `%s` | %s %s | %s |\n",
				v.Rule,
				categoryEmoji(v.Capability.Category),
				capName,
				v.Reason,
			)
		}
		fmt.Fprintf(&b, "\n")
	}

	// --- Regular capabilities section ---
	// Count non-violated novel caps (those that need human review)
	var reviewableCaps []contracts.Capability
	for _, cap := range novelCaps {
		if !cap.ContractViolated {
			reviewableCaps = append(reviewableCaps, cap)
		}
	}

	if len(novelCaps) == 0 && len(violations) == 0 {
		fmt.Fprintf(&b, "## TASS — No New Capabilities Detected\n\n")
		fmt.Fprintf(&b, "TASS scanned this PR and found no new capabilities. All clear!\n\n")
		fmt.Fprintf(&b, "%s%s -->\n", tassMarkerPrefix, scanID)
		return b.String()
	}

	if len(reviewableCaps) > 0 {
		noun := "Capability Needs"
		if len(reviewableCaps) != 1 {
			noun = "Capabilities Need"
		}
		fmt.Fprintf(&b, "## 🔍 TASS — %d New %s Review\n\n", len(reviewableCaps), noun)
		fmt.Fprintf(&b, "> ⛔ **This PR is blocked.** All capabilities must be reviewed on TASS before this branch can merge.\n\n")
		fmt.Fprintf(&b, "| # | Capability | Category | Detected In | Layer |\n")
		fmt.Fprintf(&b, "|---|------------|----------|-------------|-------|\n")

		for i, cap := range reviewableCaps {
			location := cap.Location.File
			if cap.Location.Line > 0 {
				location = fmt.Sprintf("%s:%d", cap.Location.File, cap.Location.Line)
			}
			if location == "" {
				location = "—"
			}
			fmt.Fprintf(&b, "| %d | %s | %s %s | `%s` | %s |\n",
				i+1,
				cap.Name,
				categoryEmoji(cap.Category),
				formatCategory(cap.Category),
				location,
				formatLayer(cap.Source),
			)
		}

		fmt.Fprintf(&b, "\n**[Review & Verify on TASS](%s/verify/%s)**\n\n", baseURL, scanID)

		fmt.Fprintf(&b, "<details>\n")
		fmt.Fprintf(&b, "<summary>What is this?</summary>\n\n")
		fmt.Fprintf(&b, "TASS scans PRs for newly introduced capabilities — things your code\n")
		fmt.Fprintf(&b, "can now DO that it couldn't before. Confirm what you intended,\n")
		fmt.Fprintf(&b, "revert what you didn't.\n")
		fmt.Fprintf(&b, "</details>\n\n")
	} else if len(violations) > 0 {
		// Only violations, no reviewable caps
		fmt.Fprintf(&b, "Resolve the contract violations above to unblock this PR.\n\n")
	}

	fmt.Fprintf(&b, "%s%s -->\n", tassMarkerPrefix, scanID)
	return b.String()
}

func categoryEmoji(cat contracts.CapCategory) string {
	switch cat {
	case contracts.CatExternalDep:
		return "📦"
	case contracts.CatExternalAPI:
		return "🌐"
	case contracts.CatDatabaseOp:
		return "🗄️"
	case contracts.CatNetworkAccess:
		return "🌐"
	case contracts.CatFileSystem:
		return "📁"
	case contracts.CatPrivilege:
		return "🔐"
	default:
		return "⚡"
	}
}

func formatCategory(cat contracts.CapCategory) string {
	switch cat {
	case contracts.CatExternalDep:
		return "Dependency"
	case contracts.CatExternalAPI:
		return "External API"
	case contracts.CatDatabaseOp:
		return "Database"
	case contracts.CatNetworkAccess:
		return "Network"
	case contracts.CatFileSystem:
		return "Filesystem"
	case contracts.CatPrivilege:
		return "Privilege"
	default:
		return string(cat)
	}
}

func formatLayer(layer contracts.DetectionLayer) string {
	switch layer {
	case contracts.LayerDependency:
		return "Dep Diff"
	case contracts.LayerAST:
		return "AST"
	default:
		return string(layer)
	}
}

// PostComment posts a plain (non-TASS-marker) comment on a PR or issue.
// Used by slash command responses and permission denial notices.
func PostComment(ctx context.Context, token, owner, repo string, issueNum int, body, apiBase string) error {
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", apiBase, owner, repo, issueNum)

	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("marshal comment: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("build post-comment request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("post comment: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post comment: status %d", resp.StatusCode)
	}
	return nil
}
