package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

	// --- Scanner ---
	astScanner, astErr := scanner.NewASTScannerFromDir("rules")
	if astErr != nil {
		slog.Warn("serve: AST scanner unavailable, Layer 1 disabled", "error", astErr)
		astScanner = nil
	}
	sc := scanner.New(scanner.DefaultRegistry, astScanner)

	// --- Base URL & session secret ---
	baseURL := os.Getenv("TASS_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost" + addr
	}
	sessionSecret := os.Getenv("TASS_SESSION_SECRET")
	if sessionSecret == "" {
		slog.Warn("serve: TASS_SESSION_SECRET not set — using insecure default (set this in production!)")
		sessionSecret = "tass-dev-session-secret-change-me"
	}

	// --- Auth ---
	sessions := auth.NewSessionStore(sessionSecret)
	oauthHandler := auth.NewOAuthHandler(auth.OAuthConfig{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		BaseURL:      baseURL,
	}, sessions)

	// --- Pipeline + Webhook handler ---
	pipeline := gh.NewPipeline(app, sc, store, baseURL)
	firstRun := gh.NewFirstRunPipeline(app, sc, store)
	webhookHandler := gh.NewHandler(app, store, pipeline.ScanFunc()).WithFirstRun(firstRun)

	// --- Verification decision engine ---
	verifier := gh.NewVerifier(app, store, baseURL)
	verifyHandler := server.NewVerifyHandler(verifier)

	// --- Stats handler ---
	statsHandler := server.NewStatsHandler(store)

	// --- UI handlers ---
	indexHandler := ui.NewIndexHandler(sessions)
	verifyPageHandler := ui.NewVerifyPageHandler(store, sessions, baseURL)
	dashboardHandler := ui.NewDashboardHandler(store, sessions, app)
	repoDashboardHandler := ui.NewRepoDashboardHandler(store, sessions)
	setupHandler := ui.NewSetupHandler(store, sessions)

	// --- HTTP server ---
	rawMux := server.BuildMux(server.Handlers{
		Webhook:       webhookHandler,
		APIVerify:     verifyHandler,
		APIStats:      statsHandler,
		Index:         indexHandler,
		VerifyPage:    verifyPageHandler,
		Dashboard:     server.RequireAuthMiddleware(sessions, dashboardHandler),
		RepoDashboard: server.RequireAuthMiddleware(sessions, repoDashboardHandler),
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
