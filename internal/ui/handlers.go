// Package ui provides HTTP handlers for the TASS hosted web UI.
// Templates are Templ-generated; interactivity is HTMX.
package ui

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/auth"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/internal/ui/templates"
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

// VerifyPageHandler serves GET /verify/{scan-id}.
type VerifyPageHandler struct {
	store    storage.Store
	sessions *auth.SessionStore
	baseURL  string
}

func NewVerifyPageHandler(store storage.Store, sessions *auth.SessionStore, baseURL string) *VerifyPageHandler {
	return &VerifyPageHandler{store: store, sessions: sessions, baseURL: baseURL}
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

	decMap := make(map[string]storage.VerificationDecision, len(decisions))
	for _, d := range decisions {
		decMap[d.CapabilityID] = d
	}

	data := templates.VerifyPageData{
		Scan:      scan,
		Decisions: decMap,
		Login:     sess.GitHubLogin,
		Avatar:    sess.AvatarURL,
		BaseURL:   h.baseURL,
	}
	render(w, r, http.StatusOK, templates.Verify(data))
}

// DashboardHandler serves GET /dashboard.
type DashboardHandler struct {
	store    storage.Store
	sessions *auth.SessionStore
	app      *gh.App
}

func NewDashboardHandler(store storage.Store, sessions *auth.SessionStore, app *gh.App) *DashboardHandler {
	return &DashboardHandler{store: store, sessions: sessions, app: app}
}

func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/github?return_to=/dashboard", http.StatusFound)
		return
	}

	// Find the installation for this user.
	// For v3.0 MVP: load stats for the first installation we find.
	// In v3.1 we'll add org selector support.
	ctx := r.Context()

	// Try to find an installation ID from the query param or use 0 for "all"
	instIDStr := r.URL.Query().Get("installation_id")
	var instID int64
	if instIDStr != "" {
		instID, _ = strconv.ParseInt(instIDStr, 10, 64)
	}

	data := templates.DashboardData{
		Login:   sess.GitHubLogin,
		Avatar:  sess.AvatarURL,
		OrgName: sess.GitHubLogin,
	}

	if instID > 0 {
		stats, err := h.store.GetStatsByInstallation(ctx, instID)
		if err != nil {
			slog.Error("dashboard: get stats", "installation_id", instID, "error", err)
		} else {
			data.Stats = stats
		}
	}

	render(w, r, http.StatusOK, templates.Dashboard(data))
}

// RepoDashboardHandler serves GET /dashboard/repo?repo_id=N.
type RepoDashboardHandler struct {
	store    storage.Store
	sessions *auth.SessionStore
}

func NewRepoDashboardHandler(store storage.Store, sessions *auth.SessionStore) *RepoDashboardHandler {
	return &RepoDashboardHandler{store: store, sessions: sessions}
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
	if repo != nil {
		repoName = repo.FullName
	}

	stats, err := h.store.GetStats(ctx, repoID)
	if err != nil {
		slog.Error("repo dashboard: get stats", "repo_id", repoID, "error", err)
	}

	render(w, r, http.StatusOK, templates.RepoDashboard(sess.GitHubLogin, sess.AvatarURL, repoName, stats))
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

// --- render helper ---

func render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		slog.Error("ui: render template", "error", err)
	}
}
