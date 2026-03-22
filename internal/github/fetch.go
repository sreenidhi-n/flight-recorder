package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
)

// FileInfo holds raw file content and its blob SHA (needed for PUT to update).
type FileInfo struct {
	Content []byte
	SHA     string // blob SHA — required by GitHub API when updating an existing file
}

// PRFile is one entry from GET /repos/{owner}/{repo}/pulls/{pr}/files.
type PRFile struct {
	Filename string `json:"filename"`
	Status   string `json:"status"` // "added", "modified", "removed", "renamed"
}

// FetchChangedFiles returns the list of files changed in a PR.
// Uses GET /repos/{owner}/{repo}/pulls/{pr}/files (paginates up to 300 files).
func (a *App) FetchChangedFiles(ctx context.Context, token, owner, repo string, prNumber int) ([]PRFile, error) {
	var all []PRFile
	page := 1
	for {
		url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=100&page=%d",
			a.base(), owner, repo, prNumber, page)

		var batch []PRFile
		if err := a.apiGet(ctx, token, url, &batch); err != nil {
			return nil, fmt.Errorf("fetch changed files page %d: %w", page, err)
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break // last page
		}
		page++
		if page > 3 { // cap at 300 files — enough for any PR TASS cares about
			break
		}
	}
	return all, nil
}

// FetchFile fetches a file's content AND its blob SHA from the GitHub API.
// The SHA is required when committing an update to an existing file.
// Returns nil, nil if the file does not exist at that ref.
func (a *App) FetchFile(ctx context.Context, token, owner, repo, path, ref string) (*FileInfo, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		a.base(), owner, repo, path, ref)

	var result struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		SHA      string `json:"sha"`
		Message  string `json:"message"`
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch file: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch file %s@%s: %w", path, ref, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch file %s@%s: status %d: %s", path, ref, resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fetch file %s: parse response: %w", path, err)
	}

	decoded, err := base64.StdEncoding.DecodeString(stripNewlines(result.Content))
	if err != nil {
		return nil, fmt.Errorf("fetch file %s: base64 decode: %w", path, err)
	}
	return &FileInfo{Content: decoded, SHA: result.SHA}, nil
}

// FetchFileContent fetches a single file's raw content from the GitHub API
// at the given ref (branch name or commit SHA).
// Returns nil, nil if the file does not exist at that ref.
func (a *App) FetchFileContent(ctx context.Context, token, owner, repo, path, ref string) ([]byte, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s",
		a.base(), owner, repo, path, ref)

	var result struct {
		Content  string `json:"content"`  // base64-encoded, with newlines
		Encoding string `json:"encoding"` // "base64"
		Message  string `json:"message"`  // set on 404
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch file content: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch file content %s@%s: %w", path, ref, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // file doesn't exist at this ref — caller treats as new/absent
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch file content %s@%s: status %d: %s",
			path, ref, resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fetch file content %s: parse response: %w", path, err)
	}

	// GitHub returns content as base64 with embedded newlines — strip them before decoding.
	decoded, err := base64.StdEncoding.DecodeString(stripNewlines(result.Content))
	if err != nil {
		return nil, fmt.Errorf("fetch file content %s: base64 decode: %w", path, err)
	}
	return decoded, nil
}

// FetchDepFiles fetches all known dependency files from the PR head AND base commits.
// Returns:
//   headDeps  — dep file content at head SHA (the PR's version)
//   baseDeps  — dep file content at base SHA (the target branch's version, nil = new file)
func (a *App) FetchDepFiles(
	ctx context.Context,
	token, owner, repo, headSHA, baseSHA string,
	changedFiles []PRFile,
	depFilenames map[string]struct{},
) (headDeps, baseDeps map[string][]byte, err error) {
	headDeps = make(map[string][]byte)
	baseDeps = make(map[string][]byte)

	for _, f := range changedFiles {
		if f.Status == "removed" {
			continue
		}
		base := filepath.Base(f.Filename)
		if _, isDep := depFilenames[base]; !isDep {
			continue
		}

		// Fetch head version
		headContent, err := a.FetchFileContent(ctx, token, owner, repo, f.Filename, headSHA)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch head dep %s: %w", f.Filename, err)
		}
		if headContent != nil {
			headDeps[f.Filename] = headContent
		}

		// Fetch base version (may be nil if file is new in this PR)
		baseContent, err := a.FetchFileContent(ctx, token, owner, repo, f.Filename, baseSHA)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch base dep %s: %w", f.Filename, err)
		}
		baseDeps[f.Filename] = baseContent // nil is valid (new file)
	}

	return headDeps, baseDeps, nil
}

// FetchSourceFiles fetches the head content of all changed source files.
// Only fetches files with extensions in the provided set (e.g. {".go", ".py", ".js"}).
func (a *App) FetchSourceFiles(
	ctx context.Context,
	token, owner, repo, headSHA string,
	changedFiles []PRFile,
	sourceExts map[string]struct{},
) (map[string][]byte, error) {
	result := make(map[string][]byte)

	for _, f := range changedFiles {
		if f.Status == "removed" {
			continue
		}
		ext := filepath.Ext(f.Filename)
		if _, ok := sourceExts[ext]; !ok {
			continue
		}

		content, err := a.FetchFileContent(ctx, token, owner, repo, f.Filename, headSHA)
		if err != nil {
			return nil, fmt.Errorf("fetch source file %s: %w", f.Filename, err)
		}
		if content != nil {
			result[f.Filename] = content
		}
	}

	return result, nil
}

// apiGet is a helper for authenticated GET requests that decode JSON into dest.
func (a *App) apiGet(ctx context.Context, token, url string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, dest)
}

func stripNewlines(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' && s[i] != '\r' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
