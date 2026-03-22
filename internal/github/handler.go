package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tass-security/tass/internal/storage"
)

// ScanRequest is handed off to a background worker when a PR event arrives.
// Step 3.4 will implement the actual scan; for now we just log it.
type ScanRequest struct {
	InstallationID int64
	RepoID         int64
	RepoFullName   string
	PRNumber       int
	HeadSHA        string
	BaseSHA        string
	HeadBranch     string
	BaseBranch     string
}

// ScanFunc is the callback invoked (in a goroutine) when a PR needs scanning.
// Injected at construction time so the webhook handler doesn't import scanner.
type ScanFunc func(ctx context.Context, req ScanRequest)

// Handler handles incoming GitHub webhooks.
type Handler struct {
	app      *App
	store    storage.Store
	onScan   ScanFunc
}

// NewHandler constructs a webhook handler.
// onScan is called in a background goroutine for each PR event.
// Pass nil for onScan during Step 3.3 (plumbing only — no scan yet).
func NewHandler(app *App, store storage.Store, onScan ScanFunc) *Handler {
	return &Handler{app: app, store: store, onScan: onScan}
}

// ServeHTTP is the HTTP handler for POST /webhooks/github.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Verify signature and read body
	body, err := h.app.ValidateWebhookSignature(r)
	if err != nil {
		slog.Warn("webhook: signature validation failed", "error", err, "remote", r.RemoteAddr)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// 2. Dispatch by event type
	eventType := r.Header.Get("X-GitHub-Event")
	deliveryID := r.Header.Get("X-GitHub-Delivery")

	slog.Info("webhook: received event",
		"event", eventType,
		"delivery", deliveryID,
	)

	// Respond 202 immediately — GitHub's timeout is 10s and scans take longer.
	w.WriteHeader(http.StatusAccepted)

	// 3. Handle in background so we never time out GitHub
	go func() {
		ctx := context.Background()
		switch eventType {
		case "pull_request":
			h.handlePullRequest(ctx, body, deliveryID)
		case "installation":
			h.handleInstallation(ctx, body, deliveryID)
		default:
			slog.Debug("webhook: ignoring unhandled event type", "event", eventType)
		}
	}()
}

func (h *Handler) handlePullRequest(ctx context.Context, body []byte, deliveryID string) {
	var event PullRequestEvent
	if err := json.Unmarshal(body, &event); err != nil {
		slog.Error("webhook: parse pull_request event", "error", err, "delivery", deliveryID)
		return
	}

	// Only act on opened and synchronize (new commits pushed to the PR)
	if event.Action != "opened" && event.Action != "synchronize" {
		slog.Debug("webhook: ignoring pull_request action", "action", event.Action)
		return
	}

	installationID := int64(0)
	if event.Installation != nil {
		installationID = event.Installation.ID
	}

	slog.Info("webhook: pull_request event",
		"action", event.Action,
		"repo", event.Repository.FullName,
		"pr", event.Number,
		"head_sha", event.PullRequest.Head.SHA,
		"base_sha", event.PullRequest.Base.SHA,
		"head_branch", event.PullRequest.Head.Ref,
		"base_branch", event.PullRequest.Base.Ref,
		"installation_id", installationID,
	)

	if h.onScan == nil {
		slog.Debug("webhook: no scan handler registered (Step 3.3 plumbing mode)")
		return
	}

	req := ScanRequest{
		InstallationID: installationID,
		RepoID:         event.Repository.ID,
		RepoFullName:   event.Repository.FullName,
		PRNumber:       event.Number,
		HeadSHA:        event.PullRequest.Head.SHA,
		BaseSHA:        event.PullRequest.Base.SHA,
		HeadBranch:     event.PullRequest.Head.Ref,
		BaseBranch:     event.PullRequest.Base.Ref,
	}
	h.onScan(ctx, req)
}

func (h *Handler) handleInstallation(ctx context.Context, body []byte, deliveryID string) {
	var event InstallationEvent
	if err := json.Unmarshal(body, &event); err != nil {
		slog.Error("webhook: parse installation event", "error", err, "delivery", deliveryID)
		return
	}

	switch event.Action {
	case "created":
		slog.Info("webhook: app installed",
			"installation_id", event.Installation.ID,
			"account", event.Installation.Account.Login,
			"type", event.Installation.Account.Type,
		)
		inst := storage.Installation{
			ID:           event.Installation.ID,
			AccountLogin: event.Installation.Account.Login,
			AccountType:  event.Installation.Account.Type,
		}
		if err := h.store.UpsertInstallation(ctx, inst); err != nil {
			slog.Error("webhook: store installation", "error", err,
				"installation_id", event.Installation.ID)
		}

	case "deleted":
		slog.Info("webhook: app uninstalled",
			"installation_id", event.Installation.ID,
			"account", event.Installation.Account.Login,
		)
		// Mark inactive — we keep historical data but stop acting on this installation.
		// For v3.0 we simply log; a future step adds a soft-delete column.

	default:
		slog.Debug("webhook: ignoring installation action", "action", event.Action)
	}
}

// WebhookURL returns a formatted string describing where to point GitHub.
func WebhookURL(baseURL string) string {
	return fmt.Sprintf("%s/webhooks/github", baseURL)
}
