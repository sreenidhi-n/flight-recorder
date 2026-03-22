package github_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gh "github.com/tass-security/tass/internal/github"
	"github.com/golang-jwt/jwt/v5"
)

// generateTestKey writes a fresh RSA key to a temp file and returns its path.
func generateTestKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	path := filepath.Join(t.TempDir(), "test.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func newTestApp(t *testing.T) *gh.App {
	t.Helper()
	app, err := gh.NewApp(gh.Config{
		AppID:          42,
		ClientID:       "test-client-id",
		ClientSecret:   "test-client-secret",
		WebhookSecret:  "test-webhook-secret",
		PrivateKeyPath: generateTestKey(t),
	})
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return app
}

func TestNewApp_ValidKey(t *testing.T) {
	app := newTestApp(t)
	if app == nil {
		t.Fatal("expected non-nil app")
	}
}

func TestNewApp_MissingKey(t *testing.T) {
	_, err := gh.NewApp(gh.Config{
		AppID:          1,
		PrivateKeyPath: "/nonexistent/path/key.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestNewApp_InvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(path, []byte("not valid pem content"), 0600)
	_, err := gh.NewApp(gh.Config{AppID: 1, PrivateKeyPath: path})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGenerateJWT(t *testing.T) {
	app := newTestApp(t)

	tokenStr, err := app.GenerateJWT()
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty JWT")
	}

	// Parse without verification to check claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}

	// iss must be the app ID
	iss, err := claims.GetIssuer()
	if err != nil {
		t.Fatalf("get issuer: %v", err)
	}
	if iss != fmt.Sprintf("%d", 42) {
		t.Errorf("iss: got %q, want %q", iss, "42")
	}

	// exp must be in the future
	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("get exp: %v", err)
	}
	if !exp.After(time.Now()) {
		t.Errorf("JWT is already expired: exp=%v", exp)
	}

	// iat must be in the past (we backdate 60s for clock skew)
	iat, err := claims.GetIssuedAt()
	if err != nil {
		t.Fatalf("get iat: %v", err)
	}
	if !iat.Before(time.Now()) {
		t.Errorf("iat should be in the past: iat=%v", iat)
	}

	// Algorithm must be RS256
	if token.Method.Alg() != "RS256" {
		t.Errorf("alg: got %q, want RS256", token.Method.Alg())
	}
}

func TestValidateWebhookSignature_Valid(t *testing.T) {
	app := newTestApp(t)
	payload := []byte(`{"action":"opened","number":1}`)

	// Compute the correct signature
	mac := hmac.New(sha256.New, []byte("test-webhook-secret"))
	mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)

	body, err := app.ValidateWebhookSignature(req)
	if err != nil {
		t.Fatalf("ValidateWebhookSignature: unexpected error: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Errorf("body mismatch: got %q, want %q", body, payload)
	}
}

func TestValidateWebhookSignature_Tampered(t *testing.T) {
	app := newTestApp(t)

	// Sign the original payload
	original := []byte(`{"action":"opened"}`)
	mac := hmac.New(sha256.New, []byte("test-webhook-secret"))
	mac.Write(original)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Send a different payload with the original signature
	tampered := []byte(`{"action":"closed"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(tampered))
	req.Header.Set("X-Hub-Signature-256", sig)

	_, err := app.ValidateWebhookSignature(req)
	if err == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
	if !strings.Contains(err.Error(), "signature mismatch") {
		t.Errorf("error should mention signature mismatch, got: %v", err)
	}
}

func TestValidateWebhookSignature_MissingHeader(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github",
		bytes.NewReader([]byte(`{}`)))
	// No X-Hub-Signature-256 header

	_, err := app.ValidateWebhookSignature(req)
	if err == nil {
		t.Fatal("expected error for missing signature header")
	}
}

func TestValidateWebhookSignature_WrongSecret(t *testing.T) {
	app := newTestApp(t)
	payload := []byte(`{"action":"opened"}`)

	// Sign with a DIFFERENT secret
	mac := hmac.New(sha256.New, []byte("wrong-secret"))
	mac.Write(payload)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sig)

	_, err := app.ValidateWebhookSignature(req)
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestConfigFromEnv(t *testing.T) {
	keyPath := generateTestKey(t)

	t.Setenv("TASS_GITHUB_APP_ID", "99999")
	t.Setenv("TASS_GITHUB_CLIENT_ID", "Iv1.test")
	t.Setenv("TASS_GITHUB_CLIENT_SECRET", "secret123")
	t.Setenv("TASS_GITHUB_WEBHOOK_SECRET", "whsecret")
	t.Setenv("TASS_GITHUB_PRIVATE_KEY_PATH", keyPath)

	cfg, err := gh.ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.AppID != 99999 {
		t.Errorf("AppID: got %d, want 99999", cfg.AppID)
	}
	if cfg.ClientID != "Iv1.test" {
		t.Errorf("ClientID: got %q", cfg.ClientID)
	}
}

func TestConfigFromEnv_MissingVars(t *testing.T) {
	// Unset all TASS_ env vars
	for _, key := range []string{
		"TASS_GITHUB_APP_ID", "TASS_GITHUB_CLIENT_ID",
		"TASS_GITHUB_CLIENT_SECRET", "TASS_GITHUB_WEBHOOK_SECRET",
		"TASS_GITHUB_PRIVATE_KEY_PATH",
	} {
		t.Setenv(key, "")
	}

	_, err := gh.ConfigFromEnv()
	if err == nil {
		t.Fatal("expected error for missing env vars")
	}
}
