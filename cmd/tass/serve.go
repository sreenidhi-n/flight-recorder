package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tass-security/tass/internal/auth"
	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/internal/server"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/internal/ui"
)


func runServe(args []string) error {
	addr := ":8080"
	dbPath := "tass.db"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 >= len(args) {
				return fmt.Errorf("--addr requires a value")
			}
			i++
			addr = args[i]
		case "--db":
			if i+1 >= len(args) {
				return fmt.Errorf("--db requires a value")
			}
			i++
			dbPath = args[i]
		case "--help", "-h":
			fmt.Fprintf(os.Stderr, "Usage: tass serve [--addr :8080] [--db tass.db]\n\n")
			fmt.Fprintf(os.Stderr, "Environment variables required:\n")
			fmt.Fprintf(os.Stderr, "  TASS_GITHUB_APP_ID\n")
			fmt.Fprintf(os.Stderr, "  TASS_GITHUB_CLIENT_ID\n")
			fmt.Fprintf(os.Stderr, "  TASS_GITHUB_CLIENT_SECRET\n")
			fmt.Fprintf(os.Stderr, "  TASS_GITHUB_WEBHOOK_SECRET\n")
			fmt.Fprintf(os.Stderr, "  TASS_GITHUB_PRIVATE_KEY_PATH\n")
			fmt.Fprintf(os.Stderr, "  TASS_SESSION_SECRET      (32+ random bytes as hex or any string)\n")
			fmt.Fprintf(os.Stderr, "  TASS_BASE_URL            (e.g. https://app.tass.dev)\n")
			fmt.Fprintf(os.Stderr, "  TASS_GITHUB_APP_NAME     (optional GitHub App slug — enables \"+ Add repos\" on dashboard)\n")
			fmt.Fprintf(os.Stderr, "  TASS_IMPORT_TOKEN        (optional — enables POST /api/import for CLI hybrid export)\n")
			return nil
		}
	}

	// --- Storage ---
	slog.Info("serve: opening database", "path", dbPath)
	store, err := storage.Open(dbPath)
	if err != nil {
		return fmt.Errorf("serve: open storage: %w", err)
	}
	defer store.Close()

	// --- GitHub App ---
	cfg, err := gh.ConfigFromEnv()
	if err != nil {
		return fmt.Errorf("serve: github config: %w", err)
	}
	app, err := gh.NewApp(cfg)
	if err != nil {
		return fmt.Errorf("serve: github app: %w", err)
	}
	slog.Info("serve: github app loaded", "app_id", cfg.AppID)

	// --- Scanner (embedded rules — no rules/ dir needed on the server) ---
	astScanner, astErr := buildASTScanner("./rules")
	if astErr != nil {
		slog.Warn("serve: AST scanner unavailable, Layer 1 disabled", "error", astErr)
		astScanner = nil
	}
	sc := scanner.New(scanner.DefaultRegistry, astScanner)

	// --- Base URL & session secret ---
	baseURL := strings.TrimRight(os.Getenv("TASS_BASE_URL"), "/")
	if baseURL == "" {
		baseURL = "http://localhost" + addr
	}
	sessionSecret := os.Getenv("TASS_SESSION_SECRET")
	if sessionSecret == "" {
		slog.Warn("serve: TASS_SESSION_SECRET not set — using insecure default (set this in production!)")
		sessionSecret = "tass-dev-session-secret-change-me"
	}

	// --- Auth + RBAC ---
	sessions := auth.NewSessionStore(sessionSecret)
	oauthHandler := auth.NewOAuthHandler(auth.OAuthConfig{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		BaseURL:      baseURL,
	}, sessions)
	rbacCache := auth.NewPermCache(5 * time.Minute)
	fetchPerm := auth.PermFetcher(func(ctx context.Context, token, owner, repo, login string) (string, error) {
		return app.GetCollaboratorPermission(ctx, token, owner, repo, login)
	})

	// --- Pipeline + Webhook handler ---
	pipeline := gh.NewPipeline(app, sc, store, baseURL)
	firstRun := gh.NewFirstRunPipeline(app, sc, store)

	// --- Verification decision engine ---
	verifier := gh.NewVerifier(app, store, baseURL)

	// Slash command handler (RBAC-gated, wired into webhook).
	slashHandler := gh.NewSlashCommandHandler(app, store, verifier, rbacCache)
	webhookHandler := gh.NewHandler(app, store, pipeline.ScanFunc()).
		WithFirstRun(firstRun).
		WithSlashCommands(slashHandler)

	verifyHandler := server.NewVerifyHandler(verifier)

	// --- Stats + Audit + Policy + Import handlers ---
	statsHandler := server.NewStatsHandler(store)
	auditAPIHandler := server.NewAuditHandler(store)
	auditVerifyHandler := server.NewChainVerifyHandler(store)
	auditNDJSONHandler := server.NewAuditNDJSONHandler(store)
	policyAPIHandler := server.NewPolicyHandler(store)
	importAPIHandler := server.NewImportHandler(store, baseURL)

	// --- UI handlers ---
	indexHandler := ui.NewIndexHandler(sessions)
	verifyPageHandler := ui.NewVerifyPageHandler(store, sessions, baseURL, rbacCache, fetchPerm)
	uiVerifyHandler := ui.NewUIVerifyHandler(verifier, store, sessions, baseURL, rbacCache, fetchPerm)
	dashboardHandler := ui.NewDashboardHandler(store, sessions, app, rbacCache, fetchPerm)
	repoDashboardHandler := ui.NewRepoDashboardHandler(store, sessions, rbacCache, fetchPerm)
	auditPageHandler := ui.NewAuditPageHandler(store, sessions, rbacCache, fetchPerm)
	setupHandler := ui.NewSetupHandler(store, sessions)

	// --- HTTP server ---
	rawMux := server.BuildMux(server.Handlers{
		Webhook:       webhookHandler,
		APIVerify:     verifyHandler,
		UIVerify:      uiVerifyHandler,
		APIStats:      statsHandler,
		APIAudit:       auditAPIHandler,
		APIAuditVerify: auditVerifyHandler,
		APIAuditNDJSON: auditNDJSONHandler,
		APIPolicy:     policyAPIHandler,
		APIImport:     importAPIHandler,
		Index:         indexHandler,
		VerifyPage:    verifyPageHandler,
		Dashboard:     server.RequireAuthMiddleware(sessions, dashboardHandler),
		RepoDashboard: server.RequireAuthMiddleware(sessions, repoDashboardHandler),
		Audit:         server.RequireAuthMiddleware(sessions, auditPageHandler),
		Setup:         setupHandler,
		Static:        ui.StaticHandler(),
		OAuthStart:    http.HandlerFunc(oauthHandler.HandleStart),
		OAuthCallback: http.HandlerFunc(oauthHandler.HandleCallback),
		OAuthLogout:   http.HandlerFunc(oauthHandler.HandleLogout),
	})
	mux := server.LoggingMiddleware(rawMux)
	srv := server.New(addr, mux)

	// Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Start() }()

	select {
	case err := <-serverErr:
		return fmt.Errorf("serve: server error: %w", err)
	case sig := <-quit:
		slog.Info("serve: received signal, shutting down", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
