// Package github provides GitHub App integration: JWT auth, installation tokens,
// webhook signature verification, Checks API, PR comments, and file fetching.
package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultAPIBase = "https://api.github.com"

// App is a GitHub App with JWT auth and per-installation token management.
type App struct {
	AppID         int64
	ClientID      string
	ClientSecret  string
	WebhookSecret string
	apiBase       string // override for tests; empty → uses defaultAPIBase
	privateKey    *rsa.PrivateKey

	mu     sync.Mutex
	tokens map[int64]*cachedToken // installation_id → cached token
}

// base returns the GitHub API base URL.
func (a *App) base() string {
	if a.apiBase != "" {
		return a.apiBase
	}
	return defaultAPIBase
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// Config holds all GitHub App credentials — load from environment.
type Config struct {
	AppID          int64
	ClientID       string
	ClientSecret   string
	WebhookSecret  string
	PrivateKeyPath string
	APIBaseURL     string // optional: override API base for testing
}

// NewApp constructs a GitHub App from config, loading and parsing the RSA private key.
func NewApp(cfg Config) (*App, error) {
	keyData, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("github: read private key %q: %w", cfg.PrivateKeyPath, err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("github: private key at %q is not valid PEM", cfg.PrivateKeyPath)
	}

	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("github: parse PKCS1 private key: %w", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("github: parse PKCS8 private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("github: private key is not RSA")
		}
	default:
		return nil, fmt.Errorf("github: unsupported PEM block type %q", block.Type)
	}

	return &App{
		AppID:         cfg.AppID,
		ClientID:      cfg.ClientID,
		ClientSecret:  cfg.ClientSecret,
		WebhookSecret: cfg.WebhookSecret,
		apiBase:       cfg.APIBaseURL,
		privateKey:    privateKey,
		tokens:        make(map[int64]*cachedToken),
	}, nil
}

// ConfigFromEnv loads GitHub App config from environment variables.
//
// Required env vars:
//
//	TASS_GITHUB_APP_ID
//	TASS_GITHUB_CLIENT_ID
//	TASS_GITHUB_CLIENT_SECRET
//	TASS_GITHUB_WEBHOOK_SECRET
//	TASS_GITHUB_PRIVATE_KEY_PATH
func ConfigFromEnv() (Config, error) {
	required := map[string]*string{
		"TASS_GITHUB_APP_ID":          new(string),
		"TASS_GITHUB_CLIENT_ID":       new(string),
		"TASS_GITHUB_CLIENT_SECRET":   new(string),
		"TASS_GITHUB_WEBHOOK_SECRET":  new(string),
		"TASS_GITHUB_PRIVATE_KEY_PATH": new(string),
	}

	var missing []string
	for key, ptr := range required {
		val := os.Getenv(key)
		if val == "" {
			missing = append(missing, key)
		}
		*ptr = val
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("github: missing required env vars: %v", missing)
	}

	var appID int64
	if _, err := fmt.Sscanf(os.Getenv("TASS_GITHUB_APP_ID"), "%d", &appID); err != nil {
		return Config{}, fmt.Errorf("github: TASS_GITHUB_APP_ID must be a number: %w", err)
	}

	return Config{
		AppID:          appID,
		ClientID:       os.Getenv("TASS_GITHUB_CLIENT_ID"),
		ClientSecret:   os.Getenv("TASS_GITHUB_CLIENT_SECRET"),
		WebhookSecret:  os.Getenv("TASS_GITHUB_WEBHOOK_SECRET"),
		PrivateKeyPath: os.Getenv("TASS_GITHUB_PRIVATE_KEY_PATH"),
	}, nil
}

// GenerateJWT creates a short-lived (60s) JWT for GitHub App authentication.
// Used to call App-level API endpoints and exchange for installation tokens.
func (a *App) GenerateJWT() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(), // issued-at: 60s in the past (clock skew tolerance)
		"exp": now.Add(9 * time.Minute).Unix(),   // expires in 9 min (max 10 min per GitHub docs)
		"iss": fmt.Sprintf("%d", a.AppID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("github: sign JWT: %w", err)
	}
	return signed, nil
}

// GetInstallationToken returns a valid installation access token, using the cache
// when possible and refreshing (with a 5-minute buffer) when close to expiry.
func (a *App) GetInstallationToken(ctx context.Context, installationID int64) (string, error) {
	a.mu.Lock()
	cached, ok := a.tokens[installationID]
	a.mu.Unlock()

	if ok && time.Until(cached.expiresAt) > 5*time.Minute {
		return cached.token, nil
	}

	token, expiresAt, err := a.fetchInstallationToken(ctx, installationID)
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	a.tokens[installationID] = &cachedToken{token: token, expiresAt: expiresAt}
	a.mu.Unlock()

	slog.Info("github: fetched installation token",
		"installation_id", installationID,
		"expires_at", expiresAt)
	return token, nil
}

func (a *App) fetchInstallationToken(ctx context.Context, installationID int64) (string, time.Time, error) {
	jwtToken, err := a.GenerateJWT()
	if err != nil {
		return "", time.Time{}, err
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", a.base(), installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github: build token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github: fetch installation token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("github: installation token response %d: %s",
			resp.StatusCode, string(body))
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("github: parse token response: %w", err)
	}
	return result.Token, result.ExpiresAt, nil
}

// GetRepo fetches basic repository info — used to verify token works.
func (a *App) GetRepo(ctx context.Context, installationID int64, owner, repo string) (map[string]any, error) {
	token, err := a.GetInstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s", a.base(), owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("github: build get-repo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: get repo: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: get repo %s/%s response %d: %s",
			owner, repo, resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("github: parse repo response: %w", err)
	}
	return result, nil
}
