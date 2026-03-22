package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const manifestPath = "tass.manifest.yaml"

// CommitManifest writes updated manifest YAML content to the PR branch.
// If the manifest already exists, existingSHA must be its current blob SHA
// (required by GitHub's update API). Pass "" if the file is new.
func (a *App) CommitManifest(
	ctx context.Context,
	token, owner, repo, branch string,
	content []byte,
	existingSHA string,
	prNumber int,
) error {
	encoded := base64.StdEncoding.EncodeToString(content)

	payload := map[string]any{
		"message": fmt.Sprintf("chore: update tass.manifest.yaml (PR #%d) [skip ci]", prNumber),
		"content": encoded,
		"branch":  branch,
	}
	if existingSHA != "" {
		payload["sha"] = existingSHA
	}

	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", a.base(), owner, repo, manifestPath)
	body, err := a.apiPut(ctx, token, url, payload)
	if err != nil {
		return fmt.Errorf("commit manifest to %s@%s: %w", repo, branch, err)
	}

	// Parse the response to confirm the commit was created
	var result struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		// Non-fatal — commit succeeded but we can't log the SHA
		return nil
	}
	_ = result.Commit.SHA
	return nil
}
