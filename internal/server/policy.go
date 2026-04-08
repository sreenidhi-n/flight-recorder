package server

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/tass-security/tass/internal/policy"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/manifest"
)

// PolicyHandler serves GET /api/policy?repo_id=N&format=k8s&app=myapp.
// It reads the most recent manifest snapshot from storage and generates a policy.
type PolicyHandler struct {
	store storage.Store
}

// NewPolicyHandler constructs a PolicyHandler.
func NewPolicyHandler(store storage.Store) *PolicyHandler {
	return &PolicyHandler{store: store}
}

func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	repoIDStr := q.Get("repo_id")
	format := q.Get("format")
	appName := q.Get("app")

	if format == "" {
		format = "k8s"
	}
	if appName == "" {
		appName = "myapp"
	}

	repoID, err := strconv.ParseInt(repoIDStr, 10, 64)
	if err != nil || repoID == 0 {
		http.Error(w, "repo_id required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Load the most recent committed manifest from the audit history.
	history, err := h.store.GetManifestHistory(ctx, repoID, 1)
	if err != nil {
		slog.Error("policy: get manifest history", "repo_id", repoID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var m *manifest.Manifest
	if len(history) > 0 {
		m, err = manifest.LoadBytes([]byte(history[0].ContentYAML))
		if err != nil {
			slog.Warn("policy: parse manifest from history", "error", err)
		}
	}
	if m == nil {
		m = &manifest.Manifest{Version: "1"}
	}

	opts := policy.PolicyOpts{
		AppName:   appName,
		Namespace: q.Get("namespace"),
	}

	var out []byte
	switch format {
	case "k8s":
		out, err = policy.GenerateNetworkPolicy(m, opts)
		if err == nil {
			w.Header().Set("Content-Type", "application/x-yaml")
		}
	case "iam":
		out, err = policy.GenerateIAMPolicy(m, opts)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
		}
	default:
		http.Error(w, `format must be "k8s" or "iam"`, http.StatusBadRequest)
		return
	}

	if err != nil {
		slog.Error("policy: generate", "format", format, "error", err)
		http.Error(w, "policy generation failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(out) //nolint:errcheck
}
