package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/tass-security/tass/internal/storage"
)

// StatsHandler serves GET /api/stats?repo_id=N or GET /api/stats?installation_id=N.
type StatsHandler struct {
	store storage.Store
}

// NewStatsHandler constructs a StatsHandler.
func NewStatsHandler(store storage.Store) *StatsHandler {
	return &StatsHandler{store: store}
}

func (h *StatsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	w.Header().Set("Content-Type", "application/json")

	if repoIDStr := q.Get("repo_id"); repoIDStr != "" {
		repoID, err := strconv.ParseInt(repoIDStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid repo_id"}`, http.StatusBadRequest)
			return
		}
		stats, err := h.store.GetStats(r.Context(), repoID)
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(stats)
		return
	}

	if instIDStr := q.Get("installation_id"); instIDStr != "" {
		instID, err := strconv.ParseInt(instIDStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid installation_id"}`, http.StatusBadRequest)
			return
		}
		stats, err := h.store.GetStatsByInstallation(r.Context(), instID)
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(stats)
		return
	}

	http.Error(w, `{"error":"provide repo_id or installation_id"}`, http.StatusBadRequest)
}
