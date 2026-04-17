package github

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/tass-security/tass/internal/auth"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

// SlashCommandHandler processes /tass commands in PR comments.
//
// Syntax:
//
//	/tass confirm all
//	/tass revert all
//	/tass confirm 1,2,3
//	/tass revert 4,5
//	/tass confirm 1,2 revert 3
//
// Access control: the comment author must have at least Approver (write) on
// the repository. Non-Approvers receive a reply comment and the command is
// silently discarded (AC-6 least privilege).
type SlashCommandHandler struct {
	app      *App
	store    storage.Store
	verifier *Verifier
	cache    *auth.PermCache
}

// NewSlashCommandHandler constructs a handler for /tass slash commands.
func NewSlashCommandHandler(app *App, store storage.Store, v *Verifier, cache *auth.PermCache) *SlashCommandHandler {
	return &SlashCommandHandler{app: app, store: store, verifier: v, cache: cache}
}

// Handle processes an IssueCommentEvent containing a /tass command.
// Must be called from a goroutine (does not block the webhook handler).
func (h *SlashCommandHandler) Handle(ctx context.Context, evt IssueCommentEvent) {
	if evt.Action != "created" {
		return
	}
	if evt.Issue.PullRequest == nil {
		return // comment on issue, not PR — ignore
	}

	body := strings.TrimSpace(evt.Comment.Body)
	if !strings.HasPrefix(strings.ToLower(body), "/tass") {
		return
	}

	if evt.Installation == nil {
		slog.Warn("slash_command: no installation in event")
		return
	}

	owner, repoName, ok := splitRepoFullName(evt.Repository.FullName)
	if !ok {
		return
	}

	log := slog.With("repo", evt.Repository.FullName, "pr", evt.Issue.Number, "actor", evt.Comment.User.Login)

	// --- RBAC: require Approver (write) ---
	// We need the user's OAuth token to check collaborator permissions.
	// For slash commands the user is not logged into the web UI, so we use
	// the installation token and check via the App API.
	installToken, err := h.app.GetInstallationToken(ctx, evt.Installation.ID)
	if err != nil {
		log.Error("slash_command: get installation token", "error", err)
		return
	}

	// Check permissions using the installation token (app-level check).
	perm, err := h.app.GetCollaboratorPermission(ctx, installToken, owner, repoName, evt.Comment.User.Login)
	if err != nil {
		// Post a denial comment.
		h.postComment(ctx, installToken, owner, repoName, evt.Issue.Number,
			fmt.Sprintf("@%s — unable to verify your permission on this repository. Please contact a repo admin.", evt.Comment.User.Login))
		log.Warn("slash_command: permission check failed", "error", err)
		return
	}

	role := auth.ParseRole(perm)
	if role < auth.RoleApprover {
		h.postComment(ctx, installToken, owner, repoName, evt.Issue.Number,
			fmt.Sprintf("@%s — ❌ Permission denied. Confirming or reverting capabilities requires **write** access (you have `%s`).",
				evt.Comment.User.Login, perm))
		log.Info("slash_command: denied", "user_role", role)
		return
	}

	// --- Find the pending scan for this PR ---
	repo, err := h.store.GetRepositoryByFullName(ctx, evt.Installation.ID, evt.Repository.FullName)
	if err != nil || repo == nil {
		log.Warn("slash_command: repo not found in store")
		return
	}

	scans, err := h.store.GetScansByRepo(ctx, repo.ID, 10)
	if err != nil {
		log.Error("slash_command: get scans", "error", err)
		return
	}

	var scan *storage.ScanResult
	for i := range scans {
		if scans[i].PRNumber == evt.Issue.Number && scans[i].Status == storage.StatusPending {
			scan = &scans[i]
			break
		}
	}
	if scan == nil {
		h.postComment(ctx, installToken, owner, repoName, evt.Issue.Number,
			fmt.Sprintf("@%s — no pending scan found for PR #%d.", evt.Comment.User.Login, evt.Issue.Number))
		return
	}

	// --- Parse command ---
	confirms, reverts, err := parseSlashCommand(body, len(scan.Capabilities))
	if err != nil {
		h.postComment(ctx, installToken, owner, repoName, evt.Issue.Number,
			fmt.Sprintf("@%s — ⚠️ Unrecognised command format. Usage:\n```\n/tass confirm all\n/tass revert 1,2,3\n/tass confirm 1,2 revert 3\n```", evt.Comment.User.Login))
		return
	}

	// Map 1-based display indices to capability IDs.
	indexToCap := indexedCaps(scan.Capabilities)

	// Apply decisions.
	var applied []string
	actor := evt.Comment.User.Login
	for idx := range confirms {
		cap, ok := indexToCap[idx]
		if !ok {
			continue
		}
		if _, err := h.verifier.Decide(ctx, scan.ID, cap.ID, contracts.DecisionConfirm, "via /tass slash command", actor); err != nil {
			log.Error("slash_command: confirm capability", "cap", cap.ID, "error", err)
		} else {
			applied = append(applied, fmt.Sprintf("✅ #%d %s", idx, cap.Name))
		}
	}
	for idx := range reverts {
		cap, ok := indexToCap[idx]
		if !ok {
			continue
		}
		if _, err := h.verifier.Decide(ctx, scan.ID, cap.ID, contracts.DecisionRevert, "via /tass slash command", actor); err != nil {
			log.Error("slash_command: revert capability", "cap", cap.ID, "error", err)
		} else {
			applied = append(applied, fmt.Sprintf("↩️ #%d %s", idx, cap.Name))
		}
	}

	if len(applied) > 0 {
		h.postComment(ctx, installToken, owner, repoName, evt.Issue.Number,
			fmt.Sprintf("@%s applied %d decision(s):\n%s",
				actor, len(applied), strings.Join(applied, "\n")))
	}
}

// parseSlashCommand parses the /tass command body.
// Returns sets of 1-based indices for confirms and reverts.
// capCount is used to expand "all".
func parseSlashCommand(body string, capCount int) (confirms, reverts map[int]struct{}, err error) {
	confirms = make(map[int]struct{})
	reverts = make(map[int]struct{})

	// Normalise: lowercase, strip /tass prefix.
	line := strings.TrimSpace(strings.ToLower(body))
	line = strings.TrimPrefix(line, "/tass")
	line = strings.TrimSpace(line)

	if line == "" {
		return nil, nil, fmt.Errorf("empty command")
	}

	// Split into tokens and walk through them.
	tokens := strings.Fields(line)
	current := "" // current directive: "confirm" or "revert"
	for _, tok := range tokens {
		switch tok {
		case "confirm", "revert":
			current = tok
		case "all":
			if current == "" {
				return nil, nil, fmt.Errorf("unexpected 'all' without preceding directive")
			}
			for i := 1; i <= capCount; i++ {
				if current == "confirm" {
					confirms[i] = struct{}{}
				} else {
					reverts[i] = struct{}{}
				}
			}
		default:
			if current == "" {
				return nil, nil, fmt.Errorf("unexpected token %q before confirm/revert directive", tok)
			}
			// Parse comma-separated indices.
			for _, part := range strings.Split(tok, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				n, err := strconv.Atoi(part)
				if err != nil || n < 1 {
					return nil, nil, fmt.Errorf("invalid capability index %q", part)
				}
				if current == "confirm" {
					confirms[n] = struct{}{}
				} else {
					reverts[n] = struct{}{}
				}
			}
		}
	}

	if len(confirms)+len(reverts) == 0 {
		return nil, nil, fmt.Errorf("no capabilities specified")
	}
	return confirms, reverts, nil
}

// indexedCaps maps 1-based display index to capability.
func indexedCaps(caps []contracts.Capability) map[int]contracts.Capability {
	m := make(map[int]contracts.Capability, len(caps))
	for i, c := range caps {
		m[i+1] = c
	}
	return m
}

func (h *SlashCommandHandler) postComment(ctx context.Context, token, owner, repo string, prNum int, body string) {
	if err := PostComment(ctx, token, owner, repo, prNum, body, h.app.base()); err != nil {
		slog.Error("slash_command: post comment", "error", err)
	}
}

func splitRepoFullName(fullName string) (owner, repo string, ok bool) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
