package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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
			githubAPIBase, owner, repo, existingID)
		if _, err := a.apiPatch(ctx, token, url, map[string]any{"body": body}); err != nil {
			return 0, fmt.Errorf("update comment %d: %w", existingID, err)
		}
		return existingID, nil
	}

	// Create new comment
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments",
		githubAPIBase, owner, repo, prNumber)
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
		githubAPIBase, owner, repo, prNumber)

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
func RenderComment(scanID string, novelCaps []contracts.Capability, baseURL string) string {
	var b strings.Builder

	if len(novelCaps) == 0 {
		fmt.Fprintf(&b, "## TASS — No New Capabilities Detected\n\n")
		fmt.Fprintf(&b, "TASS scanned this PR and found no new capabilities. All clear!\n\n")
		fmt.Fprintf(&b, "%s%s -->\n", tassMarkerPrefix, scanID)
		return b.String()
	}

	plural := "Capability"
	if len(novelCaps) != 1 {
		plural = "Capabilities"
	}

	fmt.Fprintf(&b, "## TASS — %d New %s Detected\n\n", len(novelCaps), plural)
	fmt.Fprintf(&b, "| # | Capability | Category | Detected In | Layer |\n")
	fmt.Fprintf(&b, "|---|------------|----------|-------------|-------|\n")

	for i, cap := range novelCaps {
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
