// Package server provides HTTP server setup, routing, and health checks.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Server wraps an http.Server with graceful shutdown.
type Server struct {
	httpServer *http.Server
	addr       string
}

// New constructs a Server with the given mux and address.
func New(addr string, mux http.Handler) *Server {
	return &Server{
		addr: addr,
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
}

// Start begins listening and serving. Blocks until the server stops.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", s.addr, err)
	}
	slog.Info("server: listening", "addr", s.addr)
	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server: serve: %w", err)
	}
	return nil
}

// Shutdown gracefully drains connections within the deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("server: shutting down")
	return s.httpServer.Shutdown(ctx)
}

// BuildMux constructs the request router.
// Routes are added here as each step is implemented.
func BuildMux(webhookHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()

	// Health check — used by Fly.io and load balancers
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"tass"}`)
	})

	// GitHub webhook endpoint
	mux.Handle("/webhooks/github", webhookHandler)

	return mux
}
