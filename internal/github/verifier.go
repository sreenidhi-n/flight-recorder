package github

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

// Verifier processes capability verification decisions.
// Called by the HTTP handler (Step 3.6) and will be called by the OAuth-aware
// handler in Phase 4 — decided_by is passed in (from session or request body).
type Verifier struct {
	app     *App
	store   storage.Store
	baseURL string
}

// NewVerifier constructs a Verifier.
func NewVerifier(app *App, store storage.Store, baseURL string) *Verifier {
	return &Verifier{app: app, store: store, baseURL: baseURL}
}

// VerifyResult is returned after processing a decision.
type VerifyResult struct {
	ScanID      string
	AllDecided  bool   // true when every capability now has a decision
	AllConfirmed bool  // true when all decisions are "confirm" (no reverts)
	ManifestCommitted bool
	CheckUpdated bool
}

// Decide records a developer's confirm/revert decision for one capability.
// If this decision completes the set (all capabilities decided), it also:
//   - Commits the updated manifest to the PR branch (confirmed caps only)
//   - Updates the GitHub Check Run
//   - Updates the PR comment
func (v *Verifier) Decide(
	ctx context.Context,
	scanID, capabilityID string,
	decision contracts.VerificationDecision,
	justification, decidedBy string,
) (*VerifyResult, error) {
	log := slog.With("scan_id", scanID, "capability_id", capabilityID, "decision", decision)

	// --- 1. Load scan ---
	scan, err := v.store.GetScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("verifier: get scan %s: %w", scanID, err)
	}
	if scan == nil {
		return nil, fmt.Errorf("verifier: scan %s not found", scanID)
	}
	if scan.Status == storage.StatusVerified {
		return nil, fmt.Errorf("verifier: scan %s is already fully verified", scanID)
	}

	// --- 2. Validate capability ID belongs to this scan ---
	if !containsCap(scan.Capabilities, capabilityID) {
		return nil, fmt.Errorf("verifier: capability %q not found in scan %s", capabilityID, scanID)
	}

	// --- 3. Store decision ---
	decisionID := fmt.Sprintf("dec-%s-%s", scanID, sanitizeID(capabilityID))
	d := storage.VerificationDecision{
		ID:            decisionID,
		ScanID:        scanID,
		CapabilityID:  capabilityID,
		Decision:      decision,
		Justification: justification,
		DecidedBy:     decidedBy,
		DecidedAt:     time.Now().UTC(),
	}
	if err := v.store.SaveDecision(ctx, d); err != nil {
		return nil, fmt.Errorf("verifier: save decision: %w", err)
	}
	log.Info("verifier: decision saved")

	// --- 4. Check if all capabilities are now decided ---
	allDecisions, err := v.store.GetDecisionsByScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("verifier: get decisions: %w", err)
	}

	result := &VerifyResult{ScanID: scanID}
	decided := decisionMap(allDecisions)
	allDecided := true
	for _, cap := range scan.Capabilities {
		if _, ok := decided[cap.ID]; !ok {
			allDecided = false
			break
		}
	}
	result.AllDecided = allDecided

	// --- 5. Get installation token + repo info ---
	// Fetched here (before the early-return) so partial decisions can also
	// update the PR comment with live progress. Errors are non-fatal.
	token, tokenErr := v.app.GetInstallationToken(ctx, scan.InstallationID)
	repo, repoErr := v.store.GetRepository(ctx, scan.RepoID)

	var owner, repoName string
	if tokenErr != nil {
		log.Error("verifier: get token (GitHub steps will be skipped)", "error", tokenErr)
	} else if repoErr != nil || repo == nil {
		log.Error("verifier: get repository (GitHub steps will be skipped)", "error", repoErr)
		tokenErr = fmt.Errorf("repo not found") // reuse as gate
	} else {
		var splitErr error
		owner, repoName, splitErr = splitFullName(repo.FullName)
		if splitErr != nil {
			log.Error("verifier: split repo name", "error", splitErr)
			tokenErr = splitErr
		}
	}

	if !allDecided {
		log.Info("verifier: partial — waiting for more decisions",
			"decided", len(decided), "total", len(scan.Capabilities))
		// Update the PR comment with a live progress view so developers can
		// see the running tally without leaving GitHub.
		if tokenErr == nil && scan.CommentID != 0 {
			progressBody := v.renderProgressComment(scanID, scan.Capabilities, decided, v.baseURL)
			commentURL := fmt.Sprintf("%s/repos/%s/%s/issues/comments/%d",
				v.app.base(), owner, repoName, scan.CommentID)
			if _, pErr := v.app.apiPatch(ctx, token, commentURL,
				map[string]any{"body": progressBody}); pErr != nil {
				log.Error("verifier: update progress comment", "error", pErr)
			} else {
				log.Info("verifier: progress comment updated",
					"decided", len(decided), "total", len(scan.Capabilities))
			}
		}
		return result, nil
	}

	// --- All decided — figure out what's confirmed vs reverted ---
	log.Info("verifier: all capabilities decided — finalizing")

	var confirmedCaps []contracts.Capability
	allConfirmed := true
	for _, cap := range scan.Capabilities {
		if decided[cap.ID] == contracts.DecisionConfirm {
			confirmedCaps = append(confirmedCaps, cap)
		} else {
			allConfirmed = false
		}
	}
	result.AllConfirmed = allConfirmed

	// --- 7. Commit updated manifest (confirmed caps only) ---
	if tokenErr == nil {
		manifestContent, commitErr := v.commitManifest(ctx, token, owner, repoName, scan, confirmedCaps)
		if commitErr != nil {
			log.Error("verifier: commit manifest", "error", commitErr)
		} else {
			result.ManifestCommitted = true
			log.Info("verifier: manifest committed")
			snap := storage.ManifestSnapshot{
				ID:          fmt.Sprintf("mh-%d-%d", scan.RepoID, time.Now().UnixMilli()),
				RepoID:      scan.RepoID,
				CommitSHA:   scan.CommitSHA,
				ContentYAML: string(manifestContent),
				CommittedBy: decidedBy,
				CommittedAt: time.Now().UTC(),
			}
			if snapErr := v.store.SaveManifestSnapshot(ctx, snap); snapErr != nil {
				log.Error("verifier: save manifest snapshot", "error", snapErr)
			}
		}
	}

	// --- 8. Update Check Run ---
	if tokenErr == nil && scan.CheckRunID != 0 {
		conclusion := ConclusionSuccess
		title := "All capabilities verified"
		summary := "Every capability detected in this PR has been reviewed. Manifest updated."

		if !allConfirmed {
			// Some were reverted — dev needs to fix their code
			conclusion = ConclusionActionRequired
			revertCount := len(scan.Capabilities) - len(confirmedCaps)
			title = fmt.Sprintf("%d capability reverted — please review", revertCount)
			summary = fmt.Sprintf(
				"%d of %d capabilities were marked for revert. "+
					"Please remove or replace the flagged code and push a new commit.",
				revertCount, len(scan.Capabilities),
			)
		}

		if err := v.app.UpdateCheckRun(ctx, token, owner, repoName,
			scan.CheckRunID, conclusion, title, summary); err != nil {
			log.Error("verifier: update check run", "error", err)
		} else {
			result.CheckUpdated = true
			log.Info("verifier: check run updated", "conclusion", conclusion)
		}
	}

	// --- 9. Update PR comment ---
	if tokenErr == nil && scan.CommentID != 0 {
		updatedBody := v.renderVerifiedComment(scanID, scan.Capabilities, decided, allConfirmed)
		commentURL := fmt.Sprintf("%s/repos/%s/%s/issues/comments/%d",
			v.app.base(), owner, repoName, scan.CommentID)
		if _, err := v.app.apiPatch(ctx, token, commentURL,
			map[string]any{"body": updatedBody}); err != nil {
			log.Error("verifier: update PR comment", "error", err)
		} else {
			log.Info("verifier: PR comment updated")
		}
	}

	// --- 10. Update scan status in storage ---
	newStatus := storage.StatusVerified
	if err := v.store.UpdateScanStatus(ctx, scanID, newStatus); err != nil {
		log.Error("verifier: update scan status", "error", err)
	}

	return result, nil
}

// commitManifest fetches the existing manifest at the PR branch (for its SHA),
// merges confirmed capabilities, commits, and returns the committed YAML content.
func (v *Verifier) commitManifest(
	ctx context.Context,
	token, owner, repo string,
	scan *storage.ScanResult,
	confirmedCaps []contracts.Capability,
) ([]byte, error) {
	// Fetch current manifest at PR branch to get blob SHA (required for update)
	existing, err := v.app.FetchFile(ctx, token, owner, repo, manifestPath, scan.HeadBranch)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest at %s: %w", scan.HeadBranch, err)
	}

	var m *manifest.Manifest
	existingSHA := ""

	if existing != nil {
		existingSHA = existing.SHA
		m, err = manifest.LoadBytes(existing.Content)
		if err != nil {
			// Corrupt manifest — start fresh rather than fail
			m = nil
		}
	}

	if m == nil {
		m = &manifest.Manifest{Version: "1"}
	}

	// Add confirmed capabilities as new entries
	now := time.Now().UTC()
	for _, cap := range confirmedCaps {
		entry := manifest.ManifestEntry{
			ID:          cap.ID,
			Name:        cap.Name,
			Category:    cap.Category,
			Source:      cap.Source,
			Status:      "confirmed",
			ConfirmedAt: &now,
			Locations:   []contracts.CodeLocation{cap.Location},
		}
		// Remove any existing entry with this ID (idempotent re-confirm)
		m.Capabilities = removeEntry(m.Capabilities, cap.ID)
		m.Capabilities = append(m.Capabilities, entry)
	}

	content, err := manifest.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	if err := v.app.CommitManifest(ctx, token, owner, repo,
		scan.HeadBranch, content, existingSHA, scan.PRNumber); err != nil {
		return nil, err
	}
	return content, nil
}

// renderProgressComment builds a live-progress PR comment shown after each
// individual decision while the scan is still partially reviewed.
func (v *Verifier) renderProgressComment(
	scanID string,
	caps []contracts.Capability,
	decided map[string]contracts.VerificationDecision,
	baseURL string,
) string {
	total := len(caps)
	confirmed, reverted, pending := 0, 0, 0
	for _, cap := range caps {
		switch decided[cap.ID] {
		case contracts.DecisionConfirm:
			confirmed++
		case contracts.DecisionRevert:
			reverted++
		default:
			pending++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## TASS — %d/%d Capabilities Reviewed\n\n", total-pending, total)

	// Tally line
	parts := []string{}
	if confirmed > 0 {
		parts = append(parts, fmt.Sprintf("✅ %d confirmed", confirmed))
	}
	if reverted > 0 {
		parts = append(parts, fmt.Sprintf("↩️ %d reverted", reverted))
	}
	if pending > 0 {
		parts = append(parts, fmt.Sprintf("⏳ %d pending", pending))
	}
	fmt.Fprintf(&b, "> %s\n\n", strings.Join(parts, " · "))

	// Per-capability table
	fmt.Fprintf(&b, "| # | Capability | Category | Status |\n")
	fmt.Fprintf(&b, "|---|------------|----------|--------|\n")
	for i, cap := range caps {
		var statusBadge string
		switch decided[cap.ID] {
		case contracts.DecisionConfirm:
			statusBadge = "✅ Confirmed"
		case contracts.DecisionRevert:
			statusBadge = "↩️ Revert"
		default:
			statusBadge = "⏳ Pending"
		}
		fmt.Fprintf(&b, "| %d | %s | %s %s | %s |\n",
			i+1, cap.Name,
			categoryEmoji(cap.Category), formatCategory(cap.Category),
			statusBadge,
		)
	}

	fmt.Fprintf(&b, "\n**[Continue reviewing on TASS](%s/verify/%s)**\n\n", baseURL, scanID)
	fmt.Fprintf(&b, "%s%s -->\n", tassMarkerPrefix, scanID)
	return b.String()
}

// renderVerifiedComment builds the final PR comment after all capabilities are decided.
func (v *Verifier) renderVerifiedComment(
	scanID string,
	caps []contracts.Capability,
	decided map[string]contracts.VerificationDecision,
	allConfirmed bool,
) string {
	var b strings.Builder

	confirmed, reverted := 0, 0
	for _, cap := range caps {
		if decided[cap.ID] == contracts.DecisionConfirm {
			confirmed++
		} else {
			reverted++
		}
	}

	if allConfirmed {
		fmt.Fprintf(&b, "## TASS — All Capabilities Verified ✅\n\n")
		fmt.Fprintf(&b, "Every capability detected in this PR has been confirmed. Manifest updated automatically.\n\n")
	} else {
		fmt.Fprintf(&b, "## TASS — Review Complete (Action Required) ↩️\n\n")
		fmt.Fprintf(&b, "Some capabilities were marked for revert. Please update your code and push a new commit.\n\n")
	}

	// Tally
	parts := []string{fmt.Sprintf("✅ %d confirmed", confirmed)}
	if reverted > 0 {
		parts = append(parts, fmt.Sprintf("↩️ %d reverted", reverted))
	}
	fmt.Fprintf(&b, "> %s\n\n", strings.Join(parts, " · "))

	// Per-row table with decision
	fmt.Fprintf(&b, "| # | Capability | Category | Decision |\n")
	fmt.Fprintf(&b, "|---|------------|----------|----------|\n")
	for i, cap := range caps {
		dec := decided[cap.ID]
		badge := "✅ Confirmed"
		if dec == contracts.DecisionRevert {
			badge = "↩️ Reverted"
		}
		fmt.Fprintf(&b, "| %d | %s | %s %s | %s |\n",
			i+1, cap.Name,
			categoryEmoji(cap.Category), formatCategory(cap.Category),
			badge,
		)
	}

	fmt.Fprintf(&b, "\n%s%s -->\n", tassMarkerPrefix, scanID)
	return b.String()
}

// --- helpers ---

func containsCap(caps []contracts.Capability, id string) bool {
	for _, c := range caps {
		if c.ID == id {
			return true
		}
	}
	return false
}

func decisionMap(decisions []storage.VerificationDecision) map[string]contracts.VerificationDecision {
	m := make(map[string]contracts.VerificationDecision, len(decisions))
	for _, d := range decisions {
		m[d.CapabilityID] = d.Decision
	}
	return m
}

func removeEntry(entries []manifest.ManifestEntry, id string) []manifest.ManifestEntry {
	out := entries[:0]
	for _, e := range entries {
		if e.ID != id {
			out = append(out, e)
		}
	}
	return out
}

// sanitizeID makes a capability ID safe for use as part of a storage key.
func sanitizeID(id string) string {
	return sanitize(id)
}
