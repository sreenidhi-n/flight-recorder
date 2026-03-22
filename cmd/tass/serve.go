package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/server"
	"github.com/tass-security/tass/internal/storage"
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

	// --- Webhook handler ---
	// onScan is nil for now (Step 3.3 — plumbing only).
	// Step 3.4 will wire in the real scan pipeline.
	webhookHandler := gh.NewHandler(app, store, nil)

	// --- HTTP server ---
	mux := server.BuildMux(webhookHandler)
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
