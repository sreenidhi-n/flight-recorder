package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tass-security/tass/internal/audit"
	"github.com/tass-security/tass/internal/auth"
	"github.com/tass-security/tass/internal/compliance"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/internal/ui/templates"
)

// ComplianceHandler serves GET /compliance/:repo
//
//	Query params:
//	  framework  soc2 | iso27001 | nist80053 | all  (default: all)
//	  format     md | json | pdf                     (default: md)
//	  since      YYYY-MM-DD or RFC3339
//
// Admin role required (GitHub maintain/admin on the repository).
// audit.Emit("compliance_report_generated") is called BEFORE returning the report.
type ComplianceHandler struct {
	store     storage.Store
	version   string
	emitter   *audit.Emitter
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
	sessions  *auth.SessionStore
}

// NewComplianceHandler creates a ComplianceHandler.
func NewComplianceHandler(
	store storage.Store,
	version string,
	emitter *audit.Emitter,
	rbacCache *auth.PermCache,
	fetchPerm auth.PermFetcher,
	sessions *auth.SessionStore,
) *ComplianceHandler {
	return &ComplianceHandler{
		store:     store,
		version:   version,
		emitter:   emitter,
		rbacCache: rbacCache,
		fetchPerm: fetchPerm,
		sessions:  sessions,
	}
}

func (h *ComplianceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract repo from URL path: /compliance/owner/repo
	repoFullName := strings.TrimPrefix(r.URL.Path, "/compliance/")
	repoFullName = strings.TrimRight(repoFullName, "/")
	if repoFullName == "" || !strings.Contains(repoFullName, "/") {
		http.Error(w, "repo path required: /compliance/owner/repo", http.StatusBadRequest)
		return
	}

	// Auth — session required.
	sess := auth.SessionFromStore(h.sessions, r)
	if sess == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	// RBAC — Admin role required on this repository.
	parts := strings.SplitN(repoFullName, "/", 2)
	if _, ok := auth.EnforceInHandler(w, r, sess.GitHubLogin, sess.AccessToken,
		parts[0], parts[1], auth.RoleAdmin, h.rbacCache, h.fetchPerm); !ok {
		return
	}

	framework := r.URL.Query().Get("framework")
	if framework == "" {
		framework = "all"
	}
	format := r.URL.Query().Get("format")
	since := r.URL.Query().Get("since")

	gen := compliance.NewGenerator(h.store, h.version)
	report, genErr := gen.Generate(r.Context(), repoFullName, framework, nil)

	// ErrChainBroken: still emit audit event, return report with 207 status.
	chainBroken := errors.Is(genErr, compliance.ErrChainBroken)
	if genErr != nil && !chainBroken {
		http.Error(w, fmt.Sprintf("generate report: %v", genErr), http.StatusInternalServerError)
		return
	}

	// Emit audit event BEFORE returning the report (spec requirement).
	_ = h.emitter.Emit(r.Context(), audit.ActionComplianceReportGenerated, repoFullName, nil, map[string]string{
		"framework":    framework,
		"format":       format,
		"chain_intact": fmt.Sprintf("%v", !chainBroken),
		"report_hash":  report.ReportHash,
	})

	status := http.StatusOK
	if chainBroken {
		status = http.StatusMultiStatus
		w.Header().Set("X-TASS-Chain-Integrity", "broken")
	}

	// HTML is the default — explicit format= selects download formats.
	switch format {
	case "json":
		body, err := report.ToJSON()
		if err != nil {
			http.Error(w, fmt.Sprintf("render json: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)

	case "pdf":
		body, err := report.ToPDF()
		if err != nil {
			http.Error(w, fmt.Sprintf("render pdf: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="tass-compliance-%s.pdf"`, strings.ReplaceAll(repoFullName, "/", "-")))
		w.WriteHeader(status)
		_, _ = w.Write(body)

	case "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="tass-compliance-%s.md"`, strings.ReplaceAll(repoFullName, "/", "-")))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(report.ToMarkdown()))

	default:
		// HTML — rendered via Templ template.
		var login, avatar string
		if sess := auth.SessionFromStore(h.sessions, r); sess != nil {
			login = sess.GitHubLogin
			avatar = sess.AvatarURL
		}
		pageData := templates.CompliancePageData{
			Login:     login,
			Avatar:    avatar,
			Report:    report,
			RepoName:  repoFullName,
			Framework: framework,
			Since:     since,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = templates.CompliancePage(pageData).Render(r.Context(), w)
	}
}
