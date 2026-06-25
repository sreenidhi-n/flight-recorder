package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
)

const checkName = "TASS Security Scan"

// checkNameRedTeam is the name of the hard-blocking fuzz-coverage check run.
// A separate check run is used so it is displayed independently in the GitHub
// PR check suite and can be required as a branch protection rule.
const checkNameRedTeam = "TASS: Dynamic Red-Team"

// CheckConclusion is the final conclusion of a check run.
type CheckConclusion string

const (
	ConclusionSuccess        CheckConclusion = "success"
	ConclusionActionRequired CheckConclusion = "action_required"
	ConclusionFailure        CheckConclusion = "failure"
)

// CreateCheckRun creates a new check run in "in_progress" state.
// Returns the check run ID needed to update it later.
func (a *App) CreateCheckRun(ctx context.Context, token, owner, repo, headSHA string) (int64, error) {
	payload := map[string]any{
		"name":       checkName,
		"head_sha":   headSHA,
		"status":     "in_progress",
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"output": map[string]any{
			"title":   "Scanning for new capabilities...",
			"summary": "TASS is analyzing your changes. Results will appear shortly.",
		},
	}

	body, err := a.apiPost(ctx, token,
		fmt.Sprintf("%s/repos/%s/%s/check-runs", a.base(), owner, repo),
		payload)
	if err != nil {
		return 0, fmt.Errorf("create check run: %w", err)
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("parse check run response: %w", err)
	}
	return result.ID, nil
}

// UpdateCheckRun marks the check run as completed with the given conclusion.
// detailsURL, if non-empty, is set as the check run's "Details" link on GitHub —
// use this to point directly at the TASS verify page for the scan.
func (a *App) UpdateCheckRun(ctx context.Context, token, owner, repo string, checkRunID int64, conclusion CheckConclusion, title, summary, detailsURL string) error {
	payload := map[string]any{
		"status":       "completed",
		"conclusion":   string(conclusion),
		"completed_at": time.Now().UTC().Format(time.RFC3339),
		"output": map[string]any{
			"title":   title,
			"summary": summary,
		},
	}
	if detailsURL != "" {
		payload["details_url"] = detailsURL
	}

	url := fmt.Sprintf("%s/repos/%s/%s/check-runs/%d", a.base(), owner, repo, checkRunID)
	if _, err := a.apiPatch(ctx, token, url, payload); err != nil {
		return fmt.Errorf("update check run %d: %w", checkRunID, err)
	}
	return nil
}

// CheckSummary builds the title and summary for a completed check run.
func CheckSummary(novelCount int, scanID, baseURL string) (title, summary string) {
	if novelCount == 0 {
		title = "No new capabilities detected"
		summary = "TASS scanned this PR and found no new capabilities. All clear!"
		return
	}

	plural := "capability"
	if novelCount != 1 {
		plural = "capabilities"
	}
	title = fmt.Sprintf("%d new %s need verification", novelCount, plural)
	summary = fmt.Sprintf(
		"%d new %s detected in this PR.\n\n**[Review & Verify on TASS](%s/verify/%s)**",
		novelCount, plural, baseURL, scanID,
	)
	return
}

// CreateRedTeamCheckRun creates the "TASS: Dynamic Red-Team" check run in
// "in_progress" state. Call this at the start of the pipeline (alongside the
// main TASS check run) so the PR shows the check immediately.
func (a *App) CreateRedTeamCheckRun(ctx context.Context, token, owner, repo, headSHA string) (int64, error) {
	payload := map[string]any{
		"name":       checkNameRedTeam,
		"head_sha":   headSHA,
		"status":     "in_progress",
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"output": map[string]any{
			"title":   "Checking fuzz test coverage...",
			"summary": "TASS is verifying that high-risk capabilities have corresponding fuzz tests.",
		},
	}
	body, err := a.apiPost(ctx, token,
		fmt.Sprintf("%s/repos/%s/%s/check-runs", a.base(), owner, repo),
		payload)
	if err != nil {
		return 0, fmt.Errorf("create red-team check run: %w", err)
	}
	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("parse red-team check run response: %w", err)
	}
	return result.ID, nil
}

// UpdateRedTeamCheckRun marks the "TASS: Dynamic Red-Team" check run as
// completed. If any of the supplied capabilities have RequiresFuzzing=true the
// conclusion is action_required (blocking), otherwise success.
func (a *App) UpdateRedTeamCheckRun(ctx context.Context, token, owner, repo string, checkRunID int64, unfuzzed []contracts.Capability) error {
	var conclusion CheckConclusion
	var title, summary string

	if len(unfuzzed) == 0 {
		conclusion = ConclusionSuccess
		title = "All high-risk capabilities have fuzz tests ✓"
		summary = "No missing fuzz stubs detected for `database_operation`, `external_api`, or `llm_execution` capabilities."
	} else {
		conclusion = ConclusionActionRequired
		plural := "capability"
		if len(unfuzzed) > 1 {
			plural = "capabilities"
		}
		title = fmt.Sprintf("%d %s require fuzz tests", len(unfuzzed), plural)

		var sb strings.Builder
		sb.WriteString("### ❌ Missing Fuzz Tests\n\n")
		sb.WriteString("The following high-risk capabilities were detected but have no `FuzzX` function " +
			"in the adjacent `_test.go` file. Add fuzz tests or run `tass gen-fuzz <capability-id>` " +
			"to generate a starter harness.\n\n")
		sb.WriteString("| Capability | Category | Location |\n")
		sb.WriteString("|---|---|---|\n")
		for _, cap := range unfuzzed {
			loc := cap.Location.File
			if cap.Location.Line > 0 {
				loc = fmt.Sprintf("%s:%d", cap.Location.File, cap.Location.Line)
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n",
				cap.Name, cap.Category, loc))
		}
		sb.WriteString("\n> **This check blocks merging.** Add the required fuzz tests and re-push to clear it.\n")
		summary = sb.String()
	}

	payload := map[string]any{
		"status":       "completed",
		"conclusion":   string(conclusion),
		"completed_at": time.Now().UTC().Format(time.RFC3339),
		"output": map[string]any{
			"title":   title,
			"summary": summary,
		},
	}
	url := fmt.Sprintf("%s/repos/%s/%s/check-runs/%d", a.base(), owner, repo, checkRunID)
	if _, err := a.apiPatch(ctx, token, url, payload); err != nil {
		return fmt.Errorf("update red-team check run %d: %w", checkRunID, err)
	}
	return nil
}

// --- HTTP helpers ---

func (a *App) apiPost(ctx context.Context, token, url string, payload any) ([]byte, error) {
	return a.apiWrite(ctx, token, http.MethodPost, url, payload)
}

func (a *App) apiPatch(ctx context.Context, token, url string, payload any) ([]byte, error) {
	return a.apiWrite(ctx, token, http.MethodPatch, url, payload)
}

func (a *App) apiPut(ctx context.Context, token, url string, payload any) ([]byte, error) {
	return a.apiWrite(ctx, token, http.MethodPut, url, payload)
}

func (a *App) apiWrite(ctx context.Context, token, method, url string, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s: status %d: %s", method, url, resp.StatusCode, string(body))
	}
	return body, nil
}
