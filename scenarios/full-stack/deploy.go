// Package main implements the Acme deployment orchestrator.
// It provisions infrastructure, runs migrations, and restarts services.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	_ "github.com/lib/pq"
)

const (
	provisioningAPI = "https://api.cloud-provider.internal/v2/provision"
	metricsEndpoint = "https://metrics.acme.internal:9090/push"
	slackHookURL    = "https://hooks.slack.com/services/T00/B00/XXXXX"
)

// Orchestrator manages the full deployment lifecycle.
type Orchestrator struct {
	db     *sql.DB
	client *http.Client
}

func NewOrchestrator(dbDSN string) (*Orchestrator, error) {
	db, err := sql.Open("postgres", dbDSN)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: open db: %w", err)
	}
	return &Orchestrator{db: db, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

// RunMigrations executes pending database migrations.
func (o *Orchestrator) RunMigrations(ctx context.Context, migrationsDir string) error {
	slog.Info("orchestrator: running migrations", "dir", migrationsDir)

	// Shell out to the migrate tool — this is a privilege operation.
	cmd := exec.CommandContext(ctx, "migrate",
		"-path", migrationsDir,
		"-database", os.Getenv("DATABASE_URL"),
		"up")
	cmd.Env = append(os.Environ(), "PGSSLMODE=require")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("orchestrator: migrate: %w — %s", err, out)
	}
	slog.Info("orchestrator: migrations complete", "output", string(out))
	return nil
}

// ProvisionEnvironment calls the cloud provisioning API to spin up resources.
func (o *Orchestrator) ProvisionEnvironment(ctx context.Context, env, version string) error {
	body := fmt.Sprintf(`{"env":%q,"version":%q}`, env, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provisioningAPI,
		newStringReader(body))
	if err != nil {
		return fmt.Errorf("orchestrator: provision request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("CLOUD_API_TOKEN"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("orchestrator: provision: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// RestartService sends a SIGHUP to a named systemd service.
func RestartService(name string) error {
	cmd := exec.Command("systemctl", "restart", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("orchestrator: restart %s: %w — %s", name, err, out)
	}
	return nil
}

// WriteBuildArtifact stores the build manifest to disk.
func WriteBuildArtifact(version string, data []byte) error {
	path := fmt.Sprintf("/var/deploy/builds/%s.json", version)
	if err := os.MkdirAll("/var/deploy/builds", 0750); err != nil {
		return fmt.Errorf("orchestrator: mkdir: %w", err)
	}
	return os.WriteFile(path, data, 0640)
}

// NotifySlack posts a deployment notification to Slack.
func NotifySlack(ctx context.Context, message string) error {
	body := fmt.Sprintf(`{"text":%q}`, message)
	resp, err := http.Post(slackHookURL, "application/json", newStringReader(body))
	if err != nil {
		return fmt.Errorf("orchestrator: slack notify: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// PushMetrics sends a Prometheus-compatible metric payload to the push gateway.
func PushMetrics(ctx context.Context, payload string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, metricsEndpoint,
		newStringReader(payload))
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("orchestrator: push metrics: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

type stringReader struct{ s string; pos int }
func newStringReader(s string) *stringReader { return &stringReader{s: s} }
func (r *stringReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.s) { return 0, fmt.Errorf("EOF") }
	n := copy(p, r.s[r.pos:])
	r.pos += n
	return n, nil
}
func (r *stringReader) Close() error { return nil }
