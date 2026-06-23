package github

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/contract"
	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

// depFilenames is the set of dependency file basenames TASS recognises.
var depFilenames = map[string]struct{}{
	"go.mod":           {},
	"requirements.txt": {},
	"package.json":     {},
}

// sourceExts is the set of source file extensions TASS AST-scans.
var sourceExts = map[string]struct{}{
	".go": {},
	".py": {},
	".js": {},
	".mjs": {},
	".cjs": {},
}

// Pipeline wires the GitHub API fetcher to the scanner and storage layer.
// It is the implementation of ScanFunc — called by the webhook handler
// in a background goroutine for each PR event.
type Pipeline struct {
	app     *App
	sc      *scanner.Scanner
	store   storage.Store
	baseURL string // e.g. "https://app.tass.dev" — used in PR comment links
}

// NewPipeline constructs a Pipeline.
// baseURL is the public-facing URL of this TASS instance (e.g. "http://localhost:8080").
// Set via TASS_BASE_URL env var in production.
func NewPipeline(app *App, sc *scanner.Scanner, store storage.Store, baseURL string) *Pipeline {
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &Pipeline{app: app, sc: sc, store: store, baseURL: baseURL}
}

// Run executes the full scan pipeline for one PR event.
// Called from a background goroutine — errors are logged, not returned.
func (p *Pipeline) Run(ctx context.Context, req ScanRequest) {
	start := time.Now()
	log := slog.With(
		"repo", req.RepoFullName,
		"pr", req.PRNumber,
		"head_sha", req.HeadSHA[:8],
	)
	log.Info("pipeline: starting scan")

	// Ensure installation + repo exist in storage
	if err := p.ensureRepo(ctx, req); err != nil {
		log.Error("pipeline: ensure repo", "error", err)
		return
	}

	// --- 1. Get installation token ---
	token, err := p.app.GetInstallationToken(ctx, req.InstallationID)
	if err != nil {
		log.Error("pipeline: get installation token", "error", err)
		return
	}

	owner, repo, err := splitFullName(req.RepoFullName)
	if err != nil {
		log.Error("pipeline: split repo name", "error", err)
		return
	}

	// --- 2. Create check run immediately (shows "in progress" on the PR) ---
	checkRunID, err := p.app.CreateCheckRun(ctx, token, owner, repo, req.HeadSHA)
	if err != nil {
		log.Error("pipeline: create check run", "error", err)
		// Non-fatal — continue the scan even if GitHub check fails
	} else {
		log.Info("pipeline: check run created", "check_run_id", checkRunID)
	}

	// --- 3. Fetch changed file list ---
	changedFiles, err := p.app.FetchChangedFiles(ctx, token, owner, repo, req.PRNumber)
	if err != nil {
		log.Error("pipeline: fetch changed files", "error", err)
		p.failCheck(ctx, token, owner, repo, checkRunID, "Failed to fetch changed files")
		return
	}
	log.Info("pipeline: fetched changed files", "count", len(changedFiles))

	// --- 4. Fetch dep files (head + base) ---
	headDeps, baseDeps, err := p.app.FetchDepFiles(
		ctx, token, owner, repo,
		req.HeadSHA, req.BaseSHA,
		changedFiles, depFilenames,
	)
	if err != nil {
		log.Error("pipeline: fetch dep files", "error", err)
		p.failCheck(ctx, token, owner, repo, checkRunID, "Failed to fetch dependency files")
		return
	}

	// --- 5. Fetch changed source files (head only) ---
	headSources, err := p.app.FetchSourceFiles(
		ctx, token, owner, repo,
		req.HeadSHA, changedFiles, sourceExts,
	)
	if err != nil {
		log.Error("pipeline: fetch source files", "error", err)
		p.failCheck(ctx, token, owner, repo, checkRunID, "Failed to fetch source files")
		return
	}

	// --- 6. Merge dep + source files into one headFiles map ---
	headFiles := make(map[string][]byte, len(headDeps)+len(headSources))
	for k, v := range headDeps {
		headFiles[k] = v
	}
	for k, v := range headSources {
		headFiles[k] = v
	}
	log.Info("pipeline: fetched files",
		"dep_files", len(headDeps),
		"source_files", len(headSources),
	)

	// --- 7. Fetch tass.manifest.yaml at base (nil = no manifest yet) ---
	var existingManifest *manifest.Manifest
	manifestContent, err := p.app.FetchFileContent(
		ctx, token, owner, repo, "tass.manifest.yaml", req.BaseSHA)
	if err != nil {
		log.Warn("pipeline: could not fetch manifest, treating as empty", "error", err)
	} else if manifestContent != nil {
		existingManifest, err = manifest.LoadBytes(manifestContent)
		if err != nil {
			log.Warn("pipeline: could not parse manifest, treating as empty", "error", err)
		}
	}

	// --- 7b. Fetch .tassignore from repo root (optional; HEAD ref) ---
	var tassIgnoreContent []byte
	if ignoreBytes, ferr := p.app.FetchFileContent(
		ctx, token, owner, repo, ".tassignore", req.HeadSHA); ferr == nil && ignoreBytes != nil {
		tassIgnoreContent = ignoreBytes
		log.Info("pipeline: loaded .tassignore", "bytes", len(tassIgnoreContent))
	}

	// --- 7c. Fetch tass.contract.yaml from base branch (optional) ---
	// Fetched from BaseSHA so the contract cannot be bypassed by updating it
	// in the same PR as the capability being blocked.
	var activeContract *contract.Contract
	if contractBytes, cerr := p.app.FetchFileContent(
		ctx, token, owner, repo, "tass.contract.yaml", req.BaseSHA); cerr == nil && contractBytes != nil {
		if activeContract, cerr = contract.Load(contractBytes); cerr != nil {
			log.Warn("pipeline: could not parse tass.contract.yaml, contract check skipped", "error", cerr)
			activeContract = nil
		} else {
			log.Info("pipeline: loaded tass.contract.yaml", "service", activeContract.Service)
		}
	}

	// --- 8. Run scanner ---
	capSet, err := p.sc.ScanRemote(headFiles, baseDeps, tassIgnoreContent)
	if err != nil {
		log.Error("pipeline: scan remote", "error", err)
		p.failCheck(ctx, token, owner, repo, checkRunID, "Scanner error")
		return
	}
	capSet.CommitSHA = req.HeadSHA
	log.Info("pipeline: scan complete", "capabilities_detected", len(capSet.Capabilities))

	// --- 9. Diff against manifest to find novel capabilities ---
	var novelCaps []contracts.Capability
	if existingManifest != nil {
		novelCaps = manifest.Diff(*capSet, existingManifest)
	} else {
		novelCaps = capSet.Capabilities
	}
	log.Info("pipeline: diff complete", "novel_capabilities", len(novelCaps))

	// --- 9b. Contract check — mark hard-block violations on novel capabilities ---
	var contractViolations []contract.Violation
	if activeContract != nil && len(novelCaps) > 0 {
		contractViolations = activeContract.Check(novelCaps)
		if len(contractViolations) > 0 {
			// Mark individual capabilities that have per-cap violations.
			violatedIDs := contract.ViolatedIDs(contractViolations)
			for i := range novelCaps {
				if reason, ok := violatedIDs[novelCaps[i].ID]; ok {
					novelCaps[i].ContractViolated = true
					novelCaps[i].ContractViolationReason = reason
				}
			}
			log.Info("pipeline: contract violations found", "count", len(contractViolations))
		}
	}

	// --- 10. Build scan ID and store result ---
	scanID := fmt.Sprintf("scan-%s-%d-%s", sanitize(req.RepoFullName), req.PRNumber, req.HeadSHA[:8])
	durationMS := time.Since(start).Milliseconds()

	// --- 10b. AI-signature detection (metadata heuristics only — no AST) ---
	// Fetch the PR's commit list so we can inspect commit message trailers.
	// Non-fatal: if the API call fails we continue with no AI signal.
	var aiCommits []CommitMeta
	if prCommits, cerr := p.app.FetchPRCommits(ctx, token, owner, repo, req.PRNumber); cerr != nil {
		log.Warn("pipeline: fetch PR commits for AI detection", "error", cerr)
	} else {
		aiCommits = prCommits
	}
	aiSig := DetectAI(req.PRAuthorLogin, aiCommits, req.PRLinesChanged)
	if aiSig.IsAIGenerated {
		log.Info("pipeline: AI-generated PR detected",
			"author", req.PRAuthorLogin,
			"signals", aiSig.Signals,
		)
	}

	// --- 11. Post PR comment ---
	commentBody := RenderComment(scanID, novelCaps, contractViolations, p.baseURL, aiSig)
	commentID, err := p.app.CreateOrUpdateComment(ctx, token, owner, repo, req.PRNumber, commentBody)
	if err != nil {
		log.Error("pipeline: post PR comment", "error", err)
		// Non-fatal — scan still stored
	} else {
		log.Info("pipeline: PR comment posted", "comment_id", commentID)
	}

	// --- 12. Update check run ---
	if checkRunID != 0 {
		conclusion := ConclusionSuccess
		if len(contractViolations) > 0 {
			// Contract violations are hard failures — cannot be resolved by review
			conclusion = ConclusionFailure
		} else if len(novelCaps) > 0 {
			conclusion = ConclusionActionRequired
		}
		title, summary := CheckSummary(len(novelCaps), scanID, p.baseURL)
		// Set details_url so the GitHub "Details" button links directly to the
		// TASS verify page for this scan. Empty string = no details link.
		detailsURL := ""
		if len(novelCaps) > 0 {
			detailsURL = p.baseURL + "/verify/" + scanID
		}
		if err := p.app.UpdateCheckRun(ctx, token, owner, repo, checkRunID, conclusion, title, summary, detailsURL); err != nil {
			log.Error("pipeline: update check run", "error", err)
		} else {
			log.Info("pipeline: check run updated", "conclusion", conclusion)
		}
	}

	// --- 13. Store scan result (with check + comment IDs for Step 3.6) ---
	scanResult := storage.ScanResult{
		ID:             scanID,
		RepoID:         req.RepoID,
		InstallationID: req.InstallationID,
		PRNumber:       req.PRNumber,
		HeadBranch:     req.HeadBranch,
		CommitSHA:      req.HeadSHA,
		BaseSHA:        req.BaseSHA,
		ScannedAt:      time.Now().UTC(),
		ScanDurationMS: durationMS,
		Capabilities:   novelCaps,
		NovelCount:     len(novelCaps),
		Status:         storage.StatusPending,
		CheckRunID:     checkRunID,
		CommentID:      commentID,
	}

	if err := p.store.SaveScan(ctx, scanResult); err != nil {
		log.Error("pipeline: save scan result", "error", err)
		return
	}

	log.Info("pipeline: complete",
		"scan_id", scanID,
		"novel_count", len(novelCaps),
		"duration_ms", durationMS,
	)
}

// failCheck updates a check run to failure with a brief message.
// Used when the pipeline itself errors before producing results.
func (p *Pipeline) failCheck(ctx context.Context, token, owner, repo string, checkRunID int64, reason string) {
	if checkRunID == 0 {
		return
	}
	_ = p.app.UpdateCheckRun(ctx, token, owner, repo, checkRunID,
		ConclusionFailure, "TASS scan error", reason, "")
}

// ensureRepo upserts the installation and repository records into storage.
func (p *Pipeline) ensureRepo(ctx context.Context, req ScanRequest) error {
	// Upsert installation (we may not have seen this one yet if it was installed
	// before this server started, or if the installation event was missed)
	inst := storage.Installation{
		ID: req.InstallationID,
		// AccountLogin/Type not available from ScanRequest — will be filled on
		// installation events. Here we just ensure the row exists.
		AccountLogin: "unknown",
		AccountType:  "unknown",
	}
	if existing, _ := p.store.GetInstallation(ctx, req.InstallationID); existing != nil {
		inst = *existing // preserve existing data
	}
	if err := p.store.UpsertInstallation(ctx, inst); err != nil {
		return fmt.Errorf("upsert installation: %w", err)
	}

	// Upsert repository
	_, defaultBranch, _ := strings.Cut(req.BaseBranch, "/")
	if defaultBranch == "" {
		defaultBranch = req.BaseBranch
	}
	repo := storage.Repository{
		ID:             req.RepoID,
		InstallationID: req.InstallationID,
		FullName:       req.RepoFullName,
		DefaultBranch:  defaultBranch,
	}
	if err := p.store.UpsertRepository(ctx, repo); err != nil {
		return fmt.Errorf("upsert repository: %w", err)
	}
	return nil
}

func splitFullName(fullName string) (owner, repo string, err error) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repo full name: %q", fullName)
	}
	return parts[0], parts[1], nil
}

// sanitize replaces characters that would be awkward in a scan ID.
func sanitize(s string) string {
	return strings.NewReplacer("/", "-", " ", "-").Replace(s)
}

// ScanFunc returns a ScanFunc backed by this pipeline, suitable for
// passing to NewHandler.
func (p *Pipeline) ScanFunc() ScanFunc {
	return p.Run
}

// knownDepFilenames returns the set of dependency file basenames for use by
// fetch helpers. Exposed so serve.go doesn't need to duplicate the list.
func KnownDepFilenames() map[string]struct{} {
	result := make(map[string]struct{}, len(depFilenames))
	for k := range depFilenames {
		result[k] = struct{}{}
	}
	return result
}

// KnownSourceExts returns the set of source extensions for use by fetch helpers.
func KnownSourceExts() map[string]struct{} {
	result := make(map[string]struct{}, len(sourceExts))
	for k := range sourceExts {
		result[k] = struct{}{}
	}
	return result
}

