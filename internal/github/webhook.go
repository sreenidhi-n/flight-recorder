package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

// ValidateWebhookSignature verifies the X-Hub-Signature-256 header on an
// incoming GitHub webhook request. Returns the raw body on success so the
// caller doesn't have to re-read it.
//
// GitHub signs the payload with HMAC-SHA256 using the webhook secret.
// We MUST use constant-time comparison (hmac.Equal) to prevent timing attacks.
func (a *App) ValidateWebhookSignature(r *http.Request) ([]byte, error) {
	sig := r.Header.Get("X-Hub-Signature-256")
	if sig == "" {
		return nil, fmt.Errorf("github: missing X-Hub-Signature-256 header")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("github: read webhook body: %w", err)
	}

	expected := computeHMAC([]byte(a.WebhookSecret), body)
	if !hmac.Equal([]byte("sha256="+expected), []byte(sig)) {
		return nil, fmt.Errorf("github: webhook signature mismatch")
	}

	return body, nil
}

func computeHMAC(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
