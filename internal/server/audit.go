package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tass-security/tass/internal/audit"
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

// --- Hash chain verify endpoint: GET /api/audit/chain/verify?tenant_id=N ---
// Admin-only. Verifies the integrity of the audit chain for a tenant.
// Returns: {"ok":true,"checked_count":N,"chain_head_hash":"..."}
// or       {"ok":false,"broken_at_id":"...","checked_count":N}

// ChainVerifyHandler handles GET /api/audit/chain/verify.
type ChainVerifyHandler struct {
	store storage.Store
}

func NewChainVerifyHandler(store storage.Store) *ChainVerifyHandler {
	return &ChainVerifyHandler{store: store}
}

func (h *ChainVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID, err := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
	if err != nil || tenantID == 0 {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}

	chainRows, err := h.store.GetAuditChainRows(r.Context(), tenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Convert storage rows to audit chain rows.
	rows := make([]audit.ChainRow, len(chainRows))
	for i, r := range chainRows {
		rows[i] = audit.ChainRow{
			ID: r.ID, Ts: r.Ts, TenantID: r.TenantID,
			ActorGHID: r.ActorGHID, ActorLogin: r.ActorLogin,
			Repo: r.Repo, Action: r.Action, TargetID: r.TargetID,
			BeforeJSON: r.BeforeJSON, AfterJSON: r.AfterJSON,
			IP: r.IP, UserAgent: r.UserAgent,
			PrevHash: r.PrevHash, Hash: r.Hash,
		}
	}

	result := audit.VerifyChain(rows)

	type resp struct {
		OK            bool   `json:"ok"`
		BrokenAtID    string `json:"broken_at_id,omitempty"`
		CheckedCount  int    `json:"checked_count"`
		ChainHeadHash string `json:"chain_head_hash,omitempty"`
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp{
		OK:            result.OK,
		BrokenAtID:    result.BrokenAtID,
		CheckedCount:  result.CheckedCount,
		ChainHeadHash: result.ChainHeadHash,
	})
}

// --- NDJSON streaming export: GET /api/audit/events.ndjson?tenant_id=N&repo=owner/repo ---
// Admin-only. Streams audit events as newline-delimited JSON.

// AuditNDJSONHandler handles GET /api/audit/events.ndjson.
type AuditNDJSONHandler struct {
	store storage.Store
}

func NewAuditNDJSONHandler(store storage.Store) *AuditNDJSONHandler {
	return &AuditNDJSONHandler{store: store}
}

func (h *AuditNDJSONHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tenantID, err := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
	if err != nil || tenantID == 0 {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}
	repo := r.URL.Query().Get("repo") // optional filter

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tass-audit-%d.ndjson"`, tenantID))

	const pageSize = 500
	encoder := json.NewEncoder(w)
	offset := 0
	for {
		events, err := h.store.GetAuditEvents(r.Context(), tenantID, repo, pageSize, offset)
		if err != nil {
			// Can't write HTTP error after headers are sent; just stop.
			return
		}
		for _, evt := range events {
			_ = encoder.Encode(evt)
		}
		if len(events) < pageSize {
			break
		}
		offset += pageSize
	}
	// Flush if the ResponseWriter supports it.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
