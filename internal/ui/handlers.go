// Package ui provides HTTP handlers for the TASS hosted web UI.
// Templates are Templ-generated; interactivity is HTMX.
package ui

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/tass-security/tass/internal/auth"
	"github.com/tass-security/tass/internal/contract"
	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/mitigation"
	"github.com/tass-security/tass/internal/policy"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/internal/ui/templates"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

//go:embed static/*
var staticFiles embed.FS

// StaticHandler serves the embedded static assets at /static/.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("ui: embed static FS: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}

// --- Handler structs ---

// IndexHandler serves GET / — landing page or redirect.
type IndexHandler struct {
	sessions *auth.SessionStore
}

func NewIndexHandler(sessions *auth.SessionStore) *IndexHandler {
	return &IndexHandler{sessions: sessions}
}

func (h *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess := auth.SessionFromStore(h.sessions, r)
	if sess != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	render(w, r, http.StatusOK, templates.Index())
}

// DocsHandler serves GET /docs — public onboarding 1-pager.
type DocsHandler struct {
	sessions *auth.SessionStore
}

func NewDocsHandler(sessions *auth.SessionStore) *DocsHandler {
	return &DocsHandler{sessions: sessions}
}

func (h *DocsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var login, avatar string
	if sess := auth.SessionFromStore(h.sessions, r); sess != nil {
		login = sess.GitHubLogin
		avatar = sess.AvatarURL
	}
	render(w, r, http.StatusOK, templates.Docs(templates.DocsPageData{Login: login, Avatar: avatar}))
}

// VerifyPageHandler serves GET /verify/{scan-id}.
type VerifyPageHandler struct {
	store     storage.Store
	sessions  *auth.SessionStore
	baseURL   string
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewVerifyPageHandler(store storage.Store, sessions *auth.SessionStore, baseURL string, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *VerifyPageHandler {
	return &VerifyPageHandler{store: store, sessions: sessions, baseURL: baseURL, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

func (h *VerifyPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromStore(h.sessions, r)
	if sess == nil {
		http.Redirect(w, r, "/auth/github?return_to="+r.URL.Path, http.StatusFound)
		return
	}

	// Extract scan ID from path: /verify/{scan-id}
	scanID := strings.TrimPrefix(r.URL.Path, "/verify/")
	if scanID == "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	ctx := r.Context()
	scan, err := h.store.GetScan(ctx, scanID)
	if err != nil || scan == nil {
		slog.Warn("verify page: scan not found", "scan_id", scanID, "error", err)
		render(w, r, http.StatusNotFound,
			templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL, "Scan not found: "+scanID))
		return
	}

	decisions, err := h.store.GetDecisionsByScan(ctx, scanID)
	if err != nil {
		slog.Error("verify page: get decisions", "scan_id", scanID, "error", err)
		render(w, r, http.StatusInternalServerError,
			templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL, "Failed to load decisions"))
		return
	}

	// RBAC: Approver (GitHub write+) may open the verify UI.
	if h.rbacCache != nil && h.fetchPerm != nil && scan.FullName != "" {
		parts := strings.SplitN(scan.FullName, "/", 2)
		if len(parts) == 2 {
			if _, err := h.rbacCache.Enforce(r.Context(), sess.GitHubLogin, sess.AccessToken,
				parts[0], parts[1], auth.RoleApprover, h.fetchPerm); err != nil {
				slog.Warn("verify page: rbac denied", "login", sess.GitHubLogin, "repo", scan.FullName, "error", err)
				render(w, r, http.StatusForbidden,
					templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL,
						"You need write access or higher on "+scan.FullName+" to review capabilities for this pull request."))
				return
			}
		}
	}

	decMap := make(map[string]storage.VerificationDecision, len(decisions))
	for _, d := range decisions {
		decMap[d.CapabilityID] = d
	}

	data := templates.VerifyPageData{
		Scan:         scan,
		Decisions:    decMap,
		Login:        sess.GitHubLogin,
		Avatar:       sess.AvatarURL,
		BaseURL:      h.baseURL,
		RepoFullName: scan.FullName,
	}
	render(w, r, http.StatusOK, templates.Verify(data))
}

// DashboardHandler serves GET /dashboard.
type DashboardHandler struct {
	store     storage.Store
	sessions  *auth.SessionStore
	app       *gh.App
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewDashboardHandler(store storage.Store, sessions *auth.SessionStore, app *gh.App, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *DashboardHandler {
	return &DashboardHandler{store: store, sessions: sessions, app: app, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/github?return_to=/dashboard", http.StatusFound)
		return
	}

	ctx := r.Context()

	// Resolve installation ID: prefer explicit query param, then auto-discover by login.
	instIDStr := r.URL.Query().Get("installation_id")
	var instID int64
	if instIDStr != "" {
		instID, _ = strconv.ParseInt(instIDStr, 10, 64)
	}
	if instID == 0 {
		inst, err := h.store.GetInstallationByLogin(ctx, sess.GitHubLogin)
		if err != nil {
			slog.Warn("dashboard: auto-discover installation failed", "login", sess.GitHubLogin, "error", err)
		} else 		if inst != nil {
			instID = inst.ID
			slog.Info("dashboard: auto-discovered installation", "login", sess.GitHubLogin, "installation_id", instID)
		}
	}

	// RBAC: org dashboard requires Developer (triage+) on at least one repo.
	// Errors from the GitHub API (e.g. private repos we can't reach) are treated as
	// non-fatal — we allow through and let per-page RBAC handle sensitive actions.
	if h.rbacCache != nil && h.fetchPerm != nil && instID > 0 {
		repos, rerr := h.store.ListRepositoriesByInstallation(ctx, instID)
		if rerr != nil {
			slog.Error("dashboard: list repos", "installation_id", instID, "error", rerr)
		} else if len(repos) > 0 {
			names := make([]string, len(repos))
			for i := range repos {
				names[i] = repos[i].FullName
			}
			ok, _ := auth.HasMinRoleOnAnyRepo(ctx, sess.GitHubLogin, sess.AccessToken, names, auth.RoleDeveloper, h.rbacCache, h.fetchPerm)
			if !ok {
				slog.Warn("dashboard: rbac denied", "login", sess.GitHubLogin, "installation_id", instID)
				render(w, r, http.StatusForbidden,
					templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL,
						"The dashboard is limited to contributors and above on at least one repository where TASS is installed."))
				return
			}
		}
	}

	var installURL string
	if h.app != nil && h.app.AppSlug != "" {
		installURL = "https://github.com/apps/" + h.app.AppSlug + "/installations/new"
	}

	data := templates.DashboardData{
		Login:         sess.GitHubLogin,
		Avatar:        sess.AvatarURL,
		OrgName:       sess.GitHubLogin,
		AppInstallURL: installURL,
	}

	if instID > 0 {
		stats, err := h.store.GetStatsByInstallation(ctx, instID)
		if err != nil {
			slog.Error("dashboard: get stats", "installation_id", instID, "error", err)
		} else {
			data.Stats = stats
		}

		recentScans, err := h.store.GetRecentScans(ctx, instID, 10)
		if err != nil {
			slog.Error("dashboard: get recent scans", "installation_id", instID, "error", err)
		} else {
			data.RecentScans = recentScans
		}

		repoStats, err := h.store.GetRepoStatsByInstallation(ctx, instID)
		if err != nil {
			slog.Error("dashboard: get repo stats", "installation_id", instID, "error", err)
		} else {
			rows := make([]templates.RepoStatRow, len(repoStats))
			for i, rs := range repoStats {
				rows[i] = templates.RepoStatRow{
					FullName:     rs.FullName,
					RepoID:       rs.RepoID,
					TotalScans:   rs.TotalScans,
					TotalCaps:    rs.TotalCaps,
					ConfirmCount: rs.ConfirmCount,
					RevertCount:  rs.RevertCount,
				}
			}
			data.RepoStatsList = rows
		}
	}

	render(w, r, http.StatusOK, templates.Dashboard(data))
}

// RepoDashboardHandler serves GET /dashboard/repo?repo_id=N.
type RepoDashboardHandler struct {
	store     storage.Store
	sessions  *auth.SessionStore
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewRepoDashboardHandler(store storage.Store, sessions *auth.SessionStore, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *RepoDashboardHandler {
	return &RepoDashboardHandler{store: store, sessions: sessions, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

func (h *RepoDashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/github?return_to="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	repoIDStr := r.URL.Query().Get("repo_id")
	repoID, err := strconv.ParseInt(repoIDStr, 10, 64)
	if err != nil || repoID == 0 {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	ctx := r.Context()
	repo, _ := h.store.GetRepository(ctx, repoID)
	repoName := fmt.Sprintf("repo #%d", repoID)
	appName := "myapp"
	if repo != nil {
		repoName = repo.FullName
		parts := strings.SplitN(repo.FullName, "/", 2)
		if len(parts) == 2 {
			appName = parts[1]
		}
	}

	if h.rbacCache != nil && h.fetchPerm != nil && repo != nil && repo.FullName != "" {
		parts := strings.SplitN(repo.FullName, "/", 2)
		if len(parts) == 2 {
			if _, err := h.rbacCache.Enforce(ctx, sess.GitHubLogin, sess.AccessToken,
				parts[0], parts[1], auth.RoleAdmin, h.fetchPerm); err != nil {
				slog.Warn("repo dashboard: rbac denied", "login", sess.GitHubLogin, "repo", repo.FullName)
				render(w, r, http.StatusForbidden,
					templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL,
						"Repository analytics and generated policies are visible to maintainers and admins only."))
				return
			}
		}
	}

	stats, err := h.store.GetStats(ctx, repoID)
	if err != nil {
		slog.Error("repo dashboard: get stats", "repo_id", repoID, "error", err)
	}

	// Generate policies from the latest committed manifest.
	var netpolYAML, iamJSON string
	if history, herr := h.store.GetManifestHistory(ctx, repoID, 1); herr == nil && len(history) > 0 {
		if m, merr := manifest.LoadBytes([]byte(history[0].ContentYAML)); merr == nil {
			opts := policy.PolicyOpts{AppName: appName}
			if b, perr := policy.GenerateNetworkPolicy(m, opts); perr == nil {
				netpolYAML = string(b)
			}
			if b, perr := policy.GenerateIAMPolicy(m, opts); perr == nil {
				iamJSON = string(b)
			}
		}
	}

	render(w, r, http.StatusOK, templates.RepoDashboard(sess.GitHubLogin, sess.AvatarURL, repoName, stats, repoID, netpolYAML, iamJSON))
}

// SetupHandler serves GET /setup?installation_id=N — post-install page.
type SetupHandler struct {
	store    storage.Store
	sessions *auth.SessionStore
}

func NewSetupHandler(store storage.Store, sessions *auth.SessionStore) *SetupHandler {
	return &SetupHandler{store: store, sessions: sessions}
}

func (h *SetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromStore(h.sessions, r)
	login, avatar := "", ""
	if sess != nil {
		login = sess.GitHubLogin
		avatar = sess.AvatarURL
	}

	ctx := r.Context()
	instIDStr := r.URL.Query().Get("installation_id")
	instID, _ := strconv.ParseInt(instIDStr, 10, 64)

	orgName := "your organization"
	if instID > 0 {
		inst, _ := h.store.GetInstallation(ctx, instID)
		if inst != nil {
			orgName = inst.AccountLogin
		}
	}

	// Repos list comes from query param (set by the installation webhook redirect)
	render(w, r, http.StatusOK, templates.Setup(login, avatar, orgName, nil))
}

// UIVerifyHandler handles POST /ui/verify — the HTMX verify endpoint.
// Accepts form data (not JSON) and returns HTML (CapabilityCardFragment).
// Requires Approver (GitHub write) role on the repository (SOC2 CC6.1/CC6.3).
type UIVerifyHandler struct {
	verifier  *gh.Verifier
	store     storage.Store
	sessions  *auth.SessionStore
	baseURL   string
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewUIVerifyHandler(verifier *gh.Verifier, store storage.Store, sessions *auth.SessionStore, baseURL string, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *UIVerifyHandler {
	return &UIVerifyHandler{verifier: verifier, store: store, sessions: sessions, baseURL: baseURL, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

func (h *UIVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	scanID := r.FormValue("scan_id")
	capID := r.FormValue("capability_id")
	decisionStr := r.FormValue("decision")
	justification := r.FormValue("justification")

	if scanID == "" || capID == "" {
		http.Error(w, "scan_id and capability_id required", http.StatusBadRequest)
		return
	}
	if decisionStr != "confirm" && decisionStr != "revert" {
		http.Error(w, `decision must be "confirm" or "revert"`, http.StatusBadRequest)
		return
	}

	sess := auth.SessionFromStore(h.sessions, r)
	decidedBy := "anonymous"
	if sess != nil {
		decidedBy = sess.GitHubLogin
	}

	// RBAC: require Approver (write) when cache and fetcher are configured.
	if h.rbacCache != nil && h.fetchPerm != nil && sess != nil {
		scan, err := h.store.GetScan(r.Context(), scanID)
		if err == nil && scan != nil && scan.FullName != "" {
			parts := strings.SplitN(scan.FullName, "/", 2)
			if len(parts) == 2 {
				if actual, err := h.rbacCache.Enforce(r.Context(), sess.GitHubLogin, sess.AccessToken,
					parts[0], parts[1], auth.RoleApprover, h.fetchPerm); err != nil {
					if r.Header.Get("HX-Request") == "true" {
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`<p style="color:#c00;padding:12px;border:1px solid #c00;border-radius:8px">You need <strong>write</strong> access on this repository to confirm or revert.</p>`))
						return
					}
					auth.WriteForbiddenJSON(w, err.Error(), auth.RoleApprover, actual)
					return
				}
			}
		}
	}

	decision := contracts.DecisionConfirm
	if decisionStr == "revert" {
		decision = contracts.DecisionRevert
	}

	result, err := h.verifier.Decide(r.Context(), scanID, capID, decision, justification, decidedBy)
	if err != nil {
		slog.Error("ui verify: decide", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	scan, err := h.store.GetScan(ctx, scanID)
	if err != nil || scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	var cap contracts.Capability
	for _, c := range scan.Capabilities {
		if c.ID == capID {
			cap = c
			break
		}
	}

	decisions, _ := h.store.GetDecisionsByScan(ctx, scanID)
	var dec storage.VerificationDecision
	for _, d := range decisions {
		if d.CapabilityID == capID {
			dec = d
			break
		}
	}

	render(w, r, http.StatusOK, templates.CapabilityCardFragment(cap, dec, scanID, h.baseURL, result.AllDecided, scan))
}

// AuditPageHandler serves GET /audit/{repo_id}[?from=...&to=...].
type AuditPageHandler struct {
	store     storage.Store
	sessions  *auth.SessionStore
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewAuditPageHandler(store storage.Store, sessions *auth.SessionStore, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *AuditPageHandler {
	return &AuditPageHandler{store: store, sessions: sessions, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

func (h *AuditPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/github?return_to="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	repoIDStr := strings.TrimPrefix(r.URL.Path, "/audit/")
	repoID, err := strconv.ParseInt(repoIDStr, 10, 64)
	if err != nil || repoID == 0 {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	ctx := r.Context()
	repo, _ := h.store.GetRepository(ctx, repoID)
	repoName := fmt.Sprintf("repo #%d", repoID)
	if repo != nil {
		repoName = repo.FullName
	}

	if h.rbacCache != nil && h.fetchPerm != nil && repo != nil && repo.FullName != "" {
		parts := strings.SplitN(repo.FullName, "/", 2)
		if len(parts) == 2 {
			if _, err := h.rbacCache.Enforce(ctx, sess.GitHubLogin, sess.AccessToken,
				parts[0], parts[1], auth.RoleAdmin, h.fetchPerm); err != nil {
				slog.Warn("audit page: rbac denied", "login", sess.GitHubLogin, "repo", repo.FullName)
				render(w, r, http.StatusForbidden,
					templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL,
						"The audit trail is visible to maintainers and admins on this repository only."))
				return
			}
		}
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	var from, to time.Time
	if fromStr != "" {
		from, _ = time.Parse("2006-01-02", fromStr)
		if from.IsZero() {
			from, _ = time.Parse(time.RFC3339, fromStr)
		}
	}
	if toStr != "" {
		to, _ = time.Parse("2006-01-02", toStr)
		if !to.IsZero() {
			to = to.Add(24*time.Hour - time.Second) // end of day
		} else {
			to, _ = time.Parse(time.RFC3339, toStr)
		}
	}

	entries, err := h.store.GetAuditTrail(ctx, repoID, from, to)
	if err != nil {
		slog.Error("audit page: get trail", "repo_id", repoID, "error", err)
	}

	data := templates.AuditPageData{
		Login:    sess.GitHubLogin,
		Avatar:   sess.AvatarURL,
		RepoID:   repoID,
		RepoName: repoName,
		From:     fromRFC3339(from),
		To:       fromRFC3339(to),
		Entries:  entries,
	}

	// HTMX partial: return just the swappable section
	if r.Header.Get("HX-Request") == "true" {
		render(w, r, http.StatusOK, templates.AuditTable(data))
		return
	}
	render(w, r, http.StatusOK, templates.Audit(data))
}

// GraphPageHandler serves GET /graph — cross-repo confirmed capability table.
// Admin-only: requires RoleAdmin on at least one repo in the installation.
type GraphPageHandler struct {
	store     storage.Store
	sessions  *auth.SessionStore
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewGraphPageHandler(store storage.Store, sessions *auth.SessionStore, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *GraphPageHandler {
	return &GraphPageHandler{store: store, sessions: sessions, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

func (h *GraphPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/github?return_to="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	ctx := r.Context()

	// Resolve installation
	instIDStr := r.URL.Query().Get("installation_id")
	var instID int64
	if instIDStr != "" {
		instID, _ = strconv.ParseInt(instIDStr, 10, 64)
	}
	if instID == 0 {
		inst, _ := h.store.GetInstallationByLogin(ctx, sess.GitHubLogin)
		if inst != nil {
			instID = inst.ID
		}
	}

	// RBAC: require Admin on at least one repo in the installation.
	if h.rbacCache != nil && h.fetchPerm != nil && instID > 0 {
		repos, err := h.store.ListRepositoriesByInstallation(ctx, instID)
		if err != nil || len(repos) == 0 {
			render(w, r, http.StatusForbidden,
				templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL,
					"No repositories found for this installation."))
			return
		}
		names := make([]string, len(repos))
		for i := range repos {
			names[i] = repos[i].FullName
		}
		ok, _ := auth.HasMinRoleOnAnyRepo(ctx, sess.GitHubLogin, sess.AccessToken, names, auth.RoleAdmin, h.rbacCache, h.fetchPerm)
		if !ok {
			slog.Warn("graph: rbac denied", "login", sess.GitHubLogin)
			render(w, r, http.StatusForbidden,
				templates.ErrorPage(sess.GitHubLogin, sess.AvatarURL,
					"The capability graph is visible to repository admins only."))
			return
		}
	}

	// Parse filters, sort, view, and cursor from query params
	q := r.URL.Query()
	filterCats := q["category"]
	filterRepos := q["repo"]
	filterFrom := q.Get("from")
	filterTo := q.Get("to")
	filterBy := q.Get("by")
	filterSearch := q.Get("q")
	format := q.Get("format")
	sortBy := q.Get("sort_by")
	sortDir := q.Get("sort_dir")
	viewMode := q.Get("view")
	if viewMode == "" {
		viewMode = "table"
	}
	cursorTimeStr := q.Get("cursor_time")
	cursorID := q.Get("cursor_id")
	isAppend := q.Get("append") == "1"

	const pageSize = 50

	var from, to, cursorTime time.Time
	if filterFrom != "" {
		if t, err := time.Parse("2006-01-02", filterFrom); err == nil {
			from = t
		}
	}
	if filterTo != "" {
		if t, err := time.Parse("2006-01-02", filterTo); err == nil {
			to = t.Add(24*time.Hour - time.Second)
		}
	}
	if cursorTimeStr != "" {
		cursorTime, _ = time.Parse(time.RFC3339, cursorTimeStr)
	}

	filter := storage.ConfirmedCapabilityFilter{
		Categories:  filterCats,
		RepoNames:   filterRepos,
		From:        from,
		To:          to,
		ConfirmedBy: filterBy,
		Search:      filterSearch,
		SortBy:      sortBy,
		SortDir:     sortDir,
		PageSize:     pageSize,
		CursorTime:  cursorTime,
		CursorID:    cursorID,
	}

	// For blast radius we need all caps (no pagination)
	if viewMode == "blast" {
		filter.PageSize = 0
		filter.CursorTime = time.Time{}
		filter.CursorID = ""
	}

	caps, err := h.store.GetConfirmedCapabilities(ctx, instID, filter)
	if err != nil {
		slog.Error("graph: get confirmed capabilities", "error", err)
		caps = nil
	}

	// Detect "has more" — store returns pageSize+1 rows when there is a next page
	hasMore := false
	var nextCursorTime, nextCursorID string
	if filter.PageSize > 0 && len(caps) > pageSize {
		hasMore = true
		caps = caps[:pageSize]
		last := caps[len(caps)-1]
		nextCursorTime = last.ConfirmedAt.UTC().Format(time.RFC3339)
		nextCursorID = last.CapabilityID
	}

	// CSV export (uses untruncated caps — re-fetch without pagination)
	if format == "csv" {
		allCaps := caps
		if hasMore {
			allFilter := filter
			allFilter.PageSize = 0
			allFilter.CursorTime = time.Time{}
			allFilter.CursorID = ""
			allCaps, _ = h.store.GetConfirmedCapabilities(ctx, instID, allFilter)
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="tass-capabilities.csv"`)
		enc := csv.NewWriter(w)
		_ = enc.Write([]string{"repo", "capability", "category", "endpoint", "confirmed_by", "confirmed_at"})
		for _, c := range allCaps {
			endpoint := c.Evidence
			if c.LocationFile != "" {
				endpoint = c.LocationFile
			}
			_ = enc.Write([]string{c.RepoFullName, c.Name, c.Category, endpoint, c.ConfirmedBy, c.ConfirmedAt.UTC().Format(time.RFC3339)})
		}
		enc.Flush()
		return
	}

	allRepos, _ := h.store.ListRepoNamesForInstallation(ctx, instID)

	data := templates.GraphPageData{
		Login:            sess.GitHubLogin,
		Avatar:           sess.AvatarURL,
		AllRepos:         allRepos,
		FilterCategories: filterCats,
		FilterRepos:      filterRepos,
		FilterFrom:       filterFrom,
		FilterTo:         filterTo,
		FilterBy:         filterBy,
		FilterSearch:     filterSearch,
		Capabilities:     caps,
		HasMore:          hasMore,
		NextCursorTime:   nextCursorTime,
		NextCursorID:     nextCursorID,
		PageSize:         pageSize,
		SortBy:           sortBy,
		SortDir:          sortDir,
		ViewMode:         viewMode,
	}

	// Pre-compute blast radius when the view is active
	if viewMode == "blast" {
		data.BlastRadius = templates.BuildBlastRadius(caps)
	}

	isHX := r.Header.Get("HX-Request") == "true"

	switch {
	case isHX && isAppend:
		// Infinite-scroll next page: return <tr> rows only (no wrapper)
		render(w, r, http.StatusOK, templates.GraphRowsBatch(data))
	case isHX && viewMode == "blast":
		render(w, r, http.StatusOK, templates.BlastRadiusView(data))
	case isHX:
		render(w, r, http.StatusOK, templates.GraphTable(data))
	default:
		render(w, r, http.StatusOK, templates.Graph(data))
	}
}

// --- GraphMitigationHandler (Task 3) ---

// GraphMitigationHandler serves GET /graph/mitigation — returns an inline
// mitigation card (action=show) or just the trigger button (action=hide).
type GraphMitigationHandler struct {
	sessions *auth.SessionStore
}

func NewGraphMitigationHandler(sessions *auth.SessionStore) *GraphMitigationHandler {
	return &GraphMitigationHandler{sessions: sessions}
}

func (h *GraphMitigationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	q := r.URL.Query()
	action := q.Get("action")
	// row_id is stamped into the URL by mitURL() in graph.templ — it matches the
	// <div id="…"> in the table row, ensuring the HTMX swap targets the right cell.
	rowID := q.Get("row_id")
	if rowID == "" {
		rowID = templates.MitRowID(q.Get("cap_id")) // fallback for direct API calls
	}

	cap := storage.ConfirmedCapability{
		CapabilityID: q.Get("cap_id"),
		Name:         q.Get("cap_name"),
		Category:     q.Get("category"),
		LocationFile: q.Get("location_file"),
		Evidence:     q.Get("evidence"),
	}

	if action == "hide" {
		render(w, r, http.StatusOK, templates.GraphMitigationButton(cap, rowID))
		return
	}

	// Build a synthetic contract.Violation for the mitigation generator.
	v := contract.Violation{
		Rule:   contract.RuleNotInAllowed,
		Reason: "capability confirmed via TASS — auto-mitigation requested",
		Capability: contracts.Capability{
			ID:   cap.CapabilityID,
			Name: cap.Name,
			Category: contracts.CapCategory(cap.Category),
			Location: contracts.CodeLocation{File: cap.LocationFile},
			RawEvidence: cap.Evidence,
		},
	}
	mit := mitigation.GenerateMitigationData(v)
	render(w, r, http.StatusOK, templates.GraphMitigationCard(mit, cap, rowID))
}

// --- ApiGraphHandler (Task 4) ---

// ApiGraphHandler serves GET /api/v1/graph — JSON representation of the
// capability graph, identical filter surface to the UI page.
type ApiGraphHandler struct {
	store     storage.Store
	sessions  *auth.SessionStore
	rbacCache *auth.PermCache
	fetchPerm auth.PermFetcher
}

func NewApiGraphHandler(store storage.Store, sessions *auth.SessionStore, rbacCache *auth.PermCache, fetchPerm auth.PermFetcher) *ApiGraphHandler {
	return &ApiGraphHandler{store: store, sessions: sessions, rbacCache: rbacCache, fetchPerm: fetchPerm}
}

// apiGraphResponse is the JSON envelope for GET /api/v1/graph.
type apiGraphResponse struct {
	Capabilities   []storage.ConfirmedCapability `json:"capabilities"`
	NextCursorTime string                        `json:"next_cursor_time,omitempty"`
	NextCursorID   string                        `json:"next_cursor_id,omitempty"`
	HasMore        bool                          `json:"has_more"`
	Total          int                           `json:"total"`
}

func (h *ApiGraphHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	ctx := r.Context()

	// Resolve installation
	instIDStr := r.URL.Query().Get("installation_id")
	var instID int64
	if instIDStr != "" {
		instID, _ = strconv.ParseInt(instIDStr, 10, 64)
	}
	if instID == 0 {
		inst, _ := h.store.GetInstallationByLogin(ctx, sess.GitHubLogin)
		if inst != nil {
			instID = inst.ID
		}
	}

	// RBAC: Admin required (same as UI)
	if h.rbacCache != nil && h.fetchPerm != nil && instID > 0 {
		repos, err := h.store.ListRepositoriesByInstallation(ctx, instID)
		if err != nil || len(repos) == 0 {
			http.Error(w, `{"error":"no repositories found"}`, http.StatusForbidden)
			return
		}
		names := make([]string, len(repos))
		for i := range repos {
			names[i] = repos[i].FullName
		}
		ok, _ := auth.HasMinRoleOnAnyRepo(ctx, sess.GitHubLogin, sess.AccessToken, names, auth.RoleAdmin, h.rbacCache, h.fetchPerm)
		if !ok {
			http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
			return
		}
	}

	q := r.URL.Query()
	filterCats := q["category"]
	filterRepos := q["repo"]
	sortBy := q.Get("sort_by")
	sortDir := q.Get("sort_dir")
	cursorTimeStr := q.Get("cursor_time")
	cursorID := q.Get("cursor_id")

	const pageSize = 50

	var from, to, cursorTime time.Time
	if s := q.Get("from"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			from = t
		}
	}
	if s := q.Get("to"); s != "" {
		if t, err := time.Parse("2006-01-02", s); err == nil {
			to = t.Add(24*time.Hour - time.Second)
		}
	}
	if cursorTimeStr != "" {
		cursorTime, _ = time.Parse(time.RFC3339, cursorTimeStr)
	}

	filter := storage.ConfirmedCapabilityFilter{
		Categories:  filterCats,
		RepoNames:   filterRepos,
		From:        from,
		To:          to,
		ConfirmedBy: q.Get("by"),
		Search:      q.Get("q"),
		SortBy:      sortBy,
		SortDir:     sortDir,
		PageSize:     pageSize,
		CursorTime:  cursorTime,
		CursorID:    cursorID,
	}

	caps, err := h.store.GetConfirmedCapabilities(ctx, instID, filter)
	if err != nil {
		slog.Error("api/graph: get confirmed capabilities", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	resp := apiGraphResponse{Total: len(caps)}
	if len(caps) > pageSize {
		resp.HasMore = true
		caps = caps[:pageSize]
		last := caps[len(caps)-1]
		resp.NextCursorTime = last.ConfirmedAt.UTC().Format(time.RFC3339)
		resp.NextCursorID = last.CapabilityID
	}
	resp.Total = len(caps)
	resp.Capabilities = caps

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func fromRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// --- render helper ---

func render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		slog.Error("ui: render template", "error", err)
	}
}
