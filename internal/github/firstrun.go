package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

const setupBranchName = "tass/initial-manifest"

// FirstRunResult is returned per-repo after the initial manifest PR is created.
type FirstRunResult struct {
	FullName string
	PRURL    string
	Err      error
}

// FirstRunPipeline handles the installation.created event:
// for each selected repo it scans the default branch, generates tass.manifest.yaml,
// and opens an initial setup PR.
type FirstRunPipeline struct {
	app   *App
	sc    *scanner.Scanner
	store storage.Store
}

// NewFirstRunPipeline constructs a FirstRunPipeline.
func NewFirstRunPipeline(app *App, sc *scanner.Scanner, store storage.Store) *FirstRunPipeline {
	return &FirstRunPipeline{app: app, sc: sc, store: store}
}

// Run processes all repos in the installation.created event.
func (p *FirstRunPipeline) Run(ctx context.Context, installationID int64, repos []InstallationRepo) []FirstRunResult {
	results := make([]FirstRunResult, 0, len(repos))
	for _, repo := range repos {
		prURL, err := p.processRepo(ctx, installationID, repo)
		results = append(results, FirstRunResult{
			FullName: repo.FullName,
			PRURL:    prURL,
			Err:      err,
		})
		if err != nil {
			slog.Error("firstrun: failed to process repo", "repo", repo.FullName, "error", err)
		} else {
			slog.Info("firstrun: manifest PR opened", "repo", repo.FullName, "pr_url", prURL)
		}
	}
	return results
}

func (p *FirstRunPipeline) processRepo(ctx context.Context, installationID int64, repo InstallationRepo) (string, error) {
	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("firstrun: invalid repo full_name %q", repo.FullName)
	}
	owner, repoName := parts[0], parts[1]

	token, err := p.app.GetInstallationToken(ctx, installationID)
	if err != nil {
		return "", fmt.Errorf("firstrun: get token for %s: %w", repo.FullName, err)
	}

	// 1. Get default branch and its HEAD SHA.
	meta, err := p.fetchRepoMeta(ctx, token, owner, repoName)
	if err != nil {
		return "", fmt.Errorf("firstrun: fetch repo meta: %w", err)
	}

	// 2. Skip if manifest already exists.
	existing, _ := p.app.FetchFile(ctx, token, owner, repoName, manifestPath, meta.defaultBranch)
	if existing != nil {
		slog.Info("firstrun: manifest already exists, skipping PR", "repo", repo.FullName)
		p.upsertRepo(ctx, installationID, repo, meta)
		return "", nil
	}

	// 3. Fetch dep files AND source files from the default branch and scan them.
	depFiles := p.collectDepFiles(ctx, token, owner, repoName, meta.defaultBranch)
	sourceFiles := p.collectSourceFiles(ctx, token, owner, repoName, meta.headSHA)

	// Merge into a single headFiles map for ScanRemote (Layer 0 + Layer 1).
	headFiles := make(map[string][]byte, len(depFiles)+len(sourceFiles))
	for k, v := range depFiles {
		headFiles[k] = v
	}
	for k, v := range sourceFiles {
		headFiles[k] = v
	}

	cs, _ := p.sc.ScanRemote(headFiles, nil)

	var caps []contracts.Capability
	if cs != nil {
		caps = cs.Capabilities
	}

	// 4. Generate manifest YAML.
	mf := manifest.FromCapabilitySet(contracts.CapabilitySet{
		Capabilities: caps,
	}, repo.FullName)
	manifestBytes, err := manifest.Marshal(mf)
	if err != nil {
		return "", fmt.Errorf("firstrun: marshal manifest: %w", err)
	}

	// 5. Create setup branch.
	if err := p.app.CreateBranch(ctx, token, owner, repoName, setupBranchName, meta.headSHA); err != nil {
		return "", fmt.Errorf("firstrun: create branch: %w", err)
	}

	// 6. Commit manifest to setup branch.
	if err := p.app.CommitManifest(ctx, token, owner, repoName, setupBranchName, manifestBytes, "", 0); err != nil {
		return "", fmt.Errorf("firstrun: commit manifest: %w", err)
	}

	// 7. Open setup PR.
	prURL, err := p.app.CreateSetupPR(ctx, token, owner, repoName, setupBranchName, meta.defaultBranch, len(caps))
	if err != nil {
		return "", fmt.Errorf("firstrun: create PR: %w", err)
	}

	// 8. Store repo in database.
	p.upsertRepo(ctx, installationID, repo, meta)

	return prURL, nil
}

type repoMeta struct {
	defaultBranch string
	headSHA       string
}

func (p *FirstRunPipeline) fetchRepoMeta(ctx context.Context, token, owner, repo string) (repoMeta, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", p.app.base(), owner, repo)
	var info struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := p.app.apiGet(ctx, token, url, &info); err != nil {
		return repoMeta{}, err
	}

	branchURL := fmt.Sprintf("%s/repos/%s/%s/branches/%s", p.app.base(), owner, repo, info.DefaultBranch)
	var branchInfo struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := p.app.apiGet(ctx, token, branchURL, &branchInfo); err != nil {
		return repoMeta{}, err
	}
	return repoMeta{defaultBranch: info.DefaultBranch, headSHA: branchInfo.Commit.SHA}, nil
}

func (p *FirstRunPipeline) collectDepFiles(ctx context.Context, token, owner, repoName, branch string) map[string][]byte {
	result := make(map[string][]byte)
	for name := range depFilenames {
		fi, err := p.app.FetchFile(ctx, token, owner, repoName, name, branch)
		if err != nil || fi == nil {
			continue
		}
		result[name] = fi.Content
	}
	return result
}

// collectSourceFiles fetches source files from the repo tree for Layer 1 AST scanning.
// Uses the git tree API (recursive) and caps at 60 files to avoid excessive API calls
// on large repositories.
func (p *FirstRunPipeline) collectSourceFiles(ctx context.Context, token, owner, repoName, sha string) map[string][]byte {
	result := make(map[string][]byte)

	treeURL := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", p.app.base(), owner, repoName, sha)
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := p.app.apiGet(ctx, token, treeURL, &tree); err != nil {
		slog.Warn("firstrun: fetch source tree", "repo", owner+"/"+repoName, "error", err)
		return result
	}

	sourceExts := map[string]bool{".go": true, ".py": true, ".js": true, ".ts": true}
	const maxFiles = 60
	fetched := 0

	for _, entry := range tree.Tree {
		if entry.Type != "blob" || fetched >= maxFiles {
			continue
		}
		if !sourceExts[filepath.Ext(entry.Path)] {
			continue
		}
		content, err := p.app.FetchFileContent(ctx, token, owner, repoName, entry.Path, sha)
		if err != nil || content == nil {
			continue
		}
		result[entry.Path] = content
		fetched++
	}

	slog.Info("firstrun: collected source files", "repo", owner+"/"+repoName, "count", fetched)
	return result
}

func (p *FirstRunPipeline) upsertRepo(ctx context.Context, installationID int64, repo InstallationRepo, meta repoMeta) {
	r := storage.Repository{
		ID:             repo.ID,
		InstallationID: installationID,
		FullName:       repo.FullName,
		DefaultBranch:  meta.defaultBranch,
	}
	if err := p.store.UpsertRepository(ctx, r); err != nil {
		slog.Error("firstrun: upsert repo", "repo", repo.FullName, "error", err)
	}
}

// CreateBranch creates a new branch from the given commit SHA.
// Silently succeeds if the branch already exists.
func (a *App) CreateBranch(ctx context.Context, token, owner, repo, branch, sha string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/git/refs", a.base(), owner, repo)
	payload := map[string]string{
		"ref": "refs/heads/" + branch,
		"sha": sha,
	}
	_, err := a.apiPost(ctx, token, url, payload)
	if err != nil {
		if strings.Contains(err.Error(), "422") || strings.Contains(err.Error(), "already exists") {
			return nil // branch already exists — fine
		}
		return fmt.Errorf("create branch %s: %w", branch, err)
	}
	return nil
}

// CreateSetupPR opens the initial manifest setup PR.
func (a *App) CreateSetupPR(ctx context.Context, token, owner, repo, head, base string, capCount int) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", a.base(), owner, repo)

	body := fmt.Sprintf(`This PR adds the initial **TASS behavioral manifest** for this repository.

TASS detected **%d existing %s** in your codebase. This manifest is the baseline — future PRs will be checked against it, and only *new* capabilities require verification.

### What is tass.manifest.yaml?

A machine-readable list of what your code can DO: external dependencies, API calls, database access, and filesystem operations. Think of it as a behavioral SBOM.

### Next steps

1. Review the manifest entries — do they look correct?
2. Merge this PR to activate TASS scanning on future PRs.

---
*Generated by [TASS](https://github.com/tass-security/tass)*`,
		capCount, pluralWord(capCount, "capability", "capabilities"))

	payload := map[string]string{
		"title": "chore: add initial TASS behavioral manifest",
		"head":  head,
		"base":  base,
		"body":  body,
	}

	respBody, err := a.apiPost(ctx, token, url, payload)
	if err != nil {
		return "", fmt.Errorf("create setup PR: %w", err)
	}
	var result struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse PR response: %w", err)
	}
	return result.HTMLURL, nil
}

func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
