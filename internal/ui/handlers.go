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
	"time"

	"github.com/a-h/templ"
	"github.com/tass-security/tass/internal/auth"
	gh "github.com/tass-security/tass/internal/github"
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
		} else if inst != nil {
			instID = inst.ID
			slog.Info("dashboard: auto-discovered installation", "login", sess.GitHubLogin, "installation_id", instID)
		}
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

		recentScans, err := h.store.GetRecentScans(ctx, instID, 10)
		if err != nil {
			slog.Error("dashboard: get recent scans", "installation_id", instID, "error", err)
		} else {
			data.RecentScans = recentScans
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
	appName := "myapp"
	if repo != nil {
		repoName = repo.FullName
		parts := strings.SplitN(repo.FullName, "/", 2)
		if len(parts) == 2 {
			appName = parts[1]
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
type UIVerifyHandler struct {
	verifier *gh.Verifier
	store    storage.Store
	sessions *auth.SessionStore
	baseURL  string
}

func NewUIVerifyHandler(verifier *gh.Verifier, store storage.Store, sessions *auth.SessionStore, baseURL string) *UIVerifyHandler {
	return &UIVerifyHandler{verifier: verifier, store: store, sessions: sessions, baseURL: baseURL}
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

	if scanID == "" || capID == "" {
		http.Error(w, "scan_id and capability_id required", http.StatusBadRequest)
		return
	}
	if decisionStr != "confirm" && decisionStr != "revert" {
		http.Error(w, `decision must be "confirm" or "revert"`, http.StatusBadRequest)
		return
	}

	decidedBy := "anonymous"
	if sess := auth.SessionFromStore(h.sessions, r); sess != nil {
		decidedBy = sess.GitHubLogin
	}

	decision := contracts.DecisionConfirm
	if decisionStr == "revert" {
		decision = contracts.DecisionRevert
	}

	result, err := h.verifier.Decide(r.Context(), scanID, capID, decision, "", decidedBy)
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
	store    storage.Store
	sessions *auth.SessionStore
}

func NewAuditPageHandler(store storage.Store, sessions *auth.SessionStore) *AuditPageHandler {
	return &AuditPageHandler{store: store, sessions: sessions}
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
