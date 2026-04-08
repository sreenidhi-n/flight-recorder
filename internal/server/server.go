// Package server provides HTTP server setup, routing, and health checks.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tass-security/tass/internal/auth"
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

// Handlers groups all HTTP handler dependencies for BuildMux.
type Handlers struct {
	Webhook       http.Handler // POST /webhooks/github
	APIVerify     http.Handler // POST /api/verify  (JSON — programmatic)
	UIVerify      http.Handler // POST /ui/verify   (form + HTML — HTMX)
	APIStats      http.Handler // GET  /api/stats
	APIAudit      http.Handler // GET  /api/audit + /api/audit/export
	APIPolicy     http.Handler // GET  /api/policy
	APIImport     http.Handler // POST /api/import (CLI export / air-gap mode)
	Index         http.Handler // GET  /
	VerifyPage    http.Handler // GET  /verify/
	Dashboard     http.Handler // GET  /dashboard
	RepoDashboard http.Handler // GET  /dashboard/repo
	Audit         http.Handler // GET  /audit/
	Setup         http.Handler // GET  /setup
	Static        http.Handler // GET  /static/
	OAuthStart    http.Handler // GET  /auth/github
	OAuthCallback http.Handler // GET  /auth/github/callback
	OAuthLogout   http.Handler // POST /auth/logout
}

// RequireAuthMiddleware wraps a handler so unauthenticated users are redirected to OAuth.
func RequireAuthMiddleware(sessions *auth.SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, _ := sessions.GetSession(r)
		if sess == nil {
			returnTo := r.URL.Path
			if r.URL.RawQuery != "" {
				returnTo += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r,
				"/auth/github?return_to="+url.QueryEscape(returnTo),
				http.StatusFound)
			return
		}
		// Attach session to context for downstream handlers.
		ctx := auth.WithSession(r.Context(), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BuildMux constructs the full request router.
func BuildMux(h Handlers) *http.ServeMux {
	mux := http.NewServeMux()

	// Health check — used by Fly.io and load balancers
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"tass"}`)
	})

	// Static assets (CSS override, etc.)
	mux.Handle("/static/", h.Static)

	// GitHub OAuth flow
	mux.Handle("/auth/github/callback", h.OAuthCallback)
	mux.Handle("/auth/github", h.OAuthStart)
	mux.Handle("/auth/logout", h.OAuthLogout)

	// Webhook receiver (no user auth — uses HMAC signature verification)
	mux.Handle("/webhooks/github", h.Webhook)

	// API endpoints
	mux.Handle("/api/verify", RateLimitMiddleware(60, time.Minute, h.APIVerify)) // JSON API
	mux.Handle("/ui/verify", RateLimitMiddleware(60, time.Minute, h.UIVerify))   // HTMX form+HTML
	mux.Handle("/api/stats", h.APIStats)
	mux.Handle("/api/audit/export", h.APIAudit)
	mux.Handle("/api/audit", h.APIAudit)
	mux.Handle("/api/policy", h.APIPolicy)
	mux.Handle("/api/import", h.APIImport)

	// Web UI pages (authenticated)
	mux.Handle("/verify/", h.VerifyPage)
	mux.Handle("/dashboard/repo", h.RepoDashboard)
	mux.Handle("/dashboard", h.Dashboard)
	mux.Handle("/audit/", h.Audit)
	mux.Handle("/setup", h.Setup)
	mux.Handle("/", h.Index)

	return mux
}
