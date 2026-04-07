package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tass-security/tass/internal/storage"
)

// AuditHandler serves:
//
//	GET /api/audit?repo_id=N[&from=RFC3339][&to=RFC3339]   → JSON timeline
//	GET /api/audit/export?repo_id=N[&from=...][&to=...]    → CSV download
type AuditHandler struct {
	store storage.Store
}

func NewAuditHandler(store storage.Store) *AuditHandler {
	return &AuditHandler{store: store}
}

func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Route: /api/audit/export vs /api/audit
	if r.URL.Path == "/api/audit/export" {
		h.handleExport(w, r)
		return
	}
	h.handleJSON(w, r)
}

func (h *AuditHandler) parseParams(r *http.Request) (repoID int64, from, to time.Time, err error) {
	repoID, err = strconv.ParseInt(r.URL.Query().Get("repo_id"), 10, 64)
	if err != nil || repoID == 0 {
		err = fmt.Errorf("repo_id required")
		return
	}
	if s := r.URL.Query().Get("from"); s != "" {
		from, err = time.Parse(time.RFC3339, s)
		if err != nil {
			err = fmt.Errorf("from: invalid RFC3339 timestamp")
			return
		}
	}
	if s := r.URL.Query().Get("to"); s != "" {
		to, err = time.Parse(time.RFC3339, s)
		if err != nil {
			err = fmt.Errorf("to: invalid RFC3339 timestamp")
			return
		}
	}
	return
}

func (h *AuditHandler) handleJSON(w http.ResponseWriter, r *http.Request) {
	repoID, from, to, err := h.parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entries, err := h.store.GetAuditTrail(r.Context(), repoID, from, to)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type jsonEntry struct {
		Kind         string `json:"kind"`
		Timestamp    string `json:"timestamp"`
		ScanID       string `json:"scan_id,omitempty"`
		CapabilityID string `json:"capability_id,omitempty"`
		Decision     string `json:"decision,omitempty"`
		DecidedBy    string `json:"decided_by,omitempty"`
		CommitSHA    string `json:"commit_sha,omitempty"`
		CommittedBy  string `json:"committed_by,omitempty"`
	}

	out := make([]jsonEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, jsonEntry{
			Kind:         string(e.Kind),
			Timestamp:    e.Timestamp.UTC().Format(time.RFC3339),
			ScanID:       e.ScanID,
			CapabilityID: e.CapabilityID,
			Decision:     e.Decision,
			DecidedBy:    e.DecidedBy,
			CommitSHA:    e.CommitSHA,
			CommittedBy:  e.CommittedBy,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *AuditHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	repoID, from, to, err := h.parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entries, err := h.store.GetAuditTrail(r.Context(), repoID, from, to)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("tass-audit-repo%d.csv", repoID)
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "type", "capability_id", "decision", "actor", "commit_sha", "scan_id"})
	for _, e := range entries {
		actor := e.DecidedBy
		if e.Kind == storage.AuditKindManifest {
			actor = e.CommittedBy
		}
		_ = cw.Write([]string{
			e.Timestamp.UTC().Format(time.RFC3339),
			string(e.Kind),
			e.CapabilityID,
			e.Decision,
			actor,
			e.CommitSHA,
			e.ScanID,
		})
	}
	cw.Flush()
}
