package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tass-security/tass/internal/auth"
	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/pkg/contracts"
)

// VerifyHandler handles POST /api/verify.
type VerifyHandler struct {
	verifier *gh.Verifier
}

// NewVerifyHandler constructs a VerifyHandler.
func NewVerifyHandler(verifier *gh.Verifier) *VerifyHandler {
	return &VerifyHandler{verifier: verifier}
}

type verifyRequest struct {
	ScanID        string `json:"scan_id"`
	CapabilityID  string `json:"capability_id"`
	Decision      string `json:"decision"`       // "confirm" or "revert"
	Justification string `json:"justification"`  // optional
	DecidedBy     string `json:"decided_by"`     // Phase 4: replaced by OAuth session
}

type verifyResponse struct {
	OK                bool   `json:"ok"`
	ScanID            string `json:"scan_id"`
	AllDecided        bool   `json:"all_decided"`
	ManifestCommitted bool   `json:"manifest_committed,omitempty"`
	CheckUpdated      bool   `json:"check_updated,omitempty"`
	Error             string `json:"error,omitempty"`
}

func (h *VerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Basic validation
	if req.ScanID == "" {
		jsonError(w, "scan_id is required", http.StatusBadRequest)
		return
	}
	if req.CapabilityID == "" {
		jsonError(w, "capability_id is required", http.StatusBadRequest)
		return
	}
	if req.Decision != "confirm" && req.Decision != "revert" {
		jsonError(w, `decision must be "confirm" or "revert"`, http.StatusBadRequest)
		return
	}
	// Prefer identity from OAuth session; fall back to request body; then "anonymous".
	if sess := auth.SessionFrom(r); sess != nil {
		req.DecidedBy = sess.GitHubLogin
	}
	if req.DecidedBy == "" {
		req.DecidedBy = "anonymous"
	}

	decision := contracts.DecisionConfirm
	if req.Decision == "revert" {
		decision = contracts.DecisionRevert
	}

	result, err := h.verifier.Decide(r.Context(),
		req.ScanID, req.CapabilityID,
		decision, req.Justification, req.DecidedBy,
	)
	if err != nil {
		slog.Error("verify: decide", "error", err,
			"scan_id", req.ScanID, "cap_id", req.CapabilityID)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verifyResponse{
		OK:                true,
		ScanID:            result.ScanID,
		AllDecided:        result.AllDecided,
		ManifestCommitted: result.ManifestCommitted,
		CheckUpdated:      result.CheckUpdated,
	})
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(verifyResponse{Error: msg})
}
