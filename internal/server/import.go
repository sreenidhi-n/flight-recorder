package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

// ImportRequest is the JSON body accepted by POST /api/import.
// The CLI sends this after a local tass scan.
type ImportRequest struct {
	// Repo is the full repository name, e.g. "owner/my-service".
	Repo string `json:"repo"`
	// Branch is the current branch being scanned (e.g. "feature/add-stripe").
	Branch string `json:"branch"`
	// CommitSHA is the HEAD commit hash (optional but useful for audit).
	CommitSHA string `json:"commit_sha,omitempty"`
	// PRNumber is the associated PR number if known (0 if not a PR).
	PRNumber int `json:"pr_number,omitempty"`
	// Capabilities is the full list of novel capabilities detected.
	Capabilities []contracts.Capability `json:"capabilities"`
}

// ImportResponse is returned to the CLI on success.
type ImportResponse struct {
	ScanID    string `json:"scan_id"`
	VerifyURL string `json:"verify_url"`
	Count     int    `json:"novel_count"`
}

// ImportHandler implements POST /api/import.
// It accepts a CapabilitySet from the CLI (air-gap / local scan mode),
// stores it as a pending scan, and returns a verify URL.
//
// Auth: Bearer token validated against TASS_IMPORT_TOKEN env var.
// If TASS_IMPORT_TOKEN is unset the endpoint is disabled (403).
type ImportHandler struct {
	store   storage.Store
	baseURL string
}

// NewImportHandler creates an ImportHandler.
func NewImportHandler(store storage.Store, baseURL string) *ImportHandler {
	return &ImportHandler{store: store, baseURL: baseURL}
}

func (h *ImportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// --- Token auth ---
	importToken := os.Getenv("TASS_IMPORT_TOKEN")
	if importToken == "" {
		http.Error(w, `{"error":"import endpoint disabled — set TASS_IMPORT_TOKEN on the server"}`,
			http.StatusForbidden)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(bearer), []byte(importToken)) != 1 {
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	// --- Parse body ---
	var req ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.Repo == "" {
		http.Error(w, `{"error":"repo is required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	log := slog.With("repo", req.Repo, "branch", req.Branch)

	// --- Resolve or create installation + repository ---
	parts := strings.SplitN(req.Repo, "/", 2)
	if len(parts) != 2 {
		http.Error(w, `{"error":"repo must be owner/name"}`, http.StatusBadRequest)
		return
	}
	owner := parts[0]

	inst, err := h.store.GetInstallationByLogin(ctx, owner)
	if err != nil || inst == nil {
		// No installation found for this owner — create a synthetic one so the
		// scan is stored under a recognisable name. Real webhook events will
		// reconcile this once the GitHub App is installed.
		synthetic := storage.Installation{
			ID:           syntheticInstallID(owner),
			AccountLogin: owner,
			AccountType:  "User",
			InstalledAt:  time.Now().UTC(),
		}
		if uErr := h.store.UpsertInstallation(ctx, synthetic); uErr != nil {
			log.Error("import: upsert synthetic installation", "error", uErr)
			http.Error(w, `{"error":"storage error"}`, http.StatusInternalServerError)
			return
		}
		inst = &synthetic
		log.Info("import: created synthetic installation", "owner", owner)
	}

	repo, err := h.store.GetRepositoryByFullName(ctx, inst.ID, req.Repo)
	if err != nil || repo == nil {
		synthetic := storage.Repository{
			ID:             syntheticRepoID(req.Repo),
			InstallationID: inst.ID,
			FullName:       req.Repo,
			DefaultBranch:  "main",
			CreatedAt:      time.Now().UTC(),
		}
		if uErr := h.store.UpsertRepository(ctx, synthetic); uErr != nil {
			log.Error("import: upsert synthetic repo", "error", uErr)
			http.Error(w, `{"error":"storage error"}`, http.StatusInternalServerError)
			return
		}
		repo = &synthetic
		log.Info("import: created synthetic repository", "repo", req.Repo)
	}

	// --- Build and save scan ---
	scanID := fmt.Sprintf("cli-%d-%s", time.Now().UnixMilli(), sanitizeForID(req.Repo))
	branch := req.Branch
	if branch == "" {
		branch = "local"
	}

	scan := storage.ScanResult{
		ID:             scanID,
		RepoID:         repo.ID,
		InstallationID: inst.ID,
		PRNumber:       req.PRNumber,
		HeadBranch:     branch,
		CommitSHA:      req.CommitSHA,
		ScannedAt:      time.Now().UTC(),
		Capabilities:   req.Capabilities,
		NovelCount:     len(req.Capabilities),
		Status:         storage.StatusPending,
	}

	if err := h.store.SaveScan(ctx, scan); err != nil {
		log.Error("import: save scan", "error", err)
		http.Error(w, `{"error":"storage error"}`, http.StatusInternalServerError)
		return
	}

	log.Info("import: scan stored", "scan_id", scanID, "novel", len(req.Capabilities))

	verifyURL := fmt.Sprintf("%s/verify/%s", h.baseURL, scanID)
	resp := ImportResponse{
		ScanID:    scanID,
		VerifyURL: verifyURL,
		Count:     len(req.Capabilities),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// syntheticInstallID generates a stable int64 from an owner login.
// Stays in a range that won't clash with real GitHub installation IDs (< 1M).
func syntheticInstallID(owner string) int64 {
	var h int64 = 5381
	for _, c := range owner {
		h = ((h << 5) + h) + int64(c)
	}
	if h < 0 {
		h = -h
	}
	return (h % 900000) + 100000 // 100000–999999
}

// syntheticRepoID generates a stable int64 from a full repo name.
func syntheticRepoID(fullName string) int64 {
	var h int64 = 5381
	for _, c := range fullName {
		h = ((h << 5) + h) + int64(c)
	}
	if h < 0 {
		h = -h
	}
	return (h%9000000)+1000000 + 1 // 1000001–9999999+1
}

// sanitizeForID makes a string safe for use in a scan ID.
func sanitizeForID(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
