// Package proxy implements an HTTP reverse proxy for internal services.
// It forwards requests to upstream APIs and caches responses in Redis.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	stripeAPIBase  = "https://api.stripe.com/v1"
	twilioAPIBase  = "https://api.twilio.com/2010-04-01"
	slackAPIBase   = "https://slack.com/api"
	internalLedger = "http://ledger.internal:8080"
)

var defaultClient = &http.Client{Timeout: 15 * time.Second}

// FetchStripeCustomer retrieves a customer object from the Stripe API.
func FetchStripeCustomer(ctx context.Context, customerID, apiKey string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/customers/%s", stripeAPIBase, customerID), nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: stripe request: %w", err)
	}
	req.SetBasicAuth(apiKey, "")

	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("proxy: stripe fetch: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("proxy: stripe decode: %w", err)
	}
	return result, nil
}

// SendSMSViaTwilio posts an SMS message through the Twilio REST API.
func SendSMSViaTwilio(ctx context.Context, to, from, body, sid, token string) error {
	url := fmt.Sprintf("%s/Accounts/%s/Messages.json", twilioAPIBase, sid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("proxy: twilio request: %w", err)
	}
	req.SetBasicAuth(sid, token)

	resp, err := defaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxy: twilio send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("proxy: twilio error %d: %s", resp.StatusCode, b)
	}
	return nil
}

// PostSlackMessage sends a message to a Slack channel via the Web API.
func PostSlackMessage(ctx context.Context, channel, text, botToken string) error {
	payload, _ := json.Marshal(map[string]string{"channel": channel, "text": text})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		slackAPIBase+"/chat.postMessage",
		io.NopCloser(newBytesReader(payload)))
	if err != nil {
		return fmt.Errorf("proxy: slack request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+botToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := defaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxy: slack post: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// ForwardToLedger relays a transaction event to the internal ledger service.
func ForwardToLedger(ctx context.Context, event map[string]any) error {
	b, _ := json.Marshal(event)
	resp, err := http.Post(internalLedger+"/events", "application/json", newBytesReader(b))
	if err != nil {
		return fmt.Errorf("proxy: ledger forward: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("proxy: ledger returned %d", resp.StatusCode)
	}
	return nil
}

type bytesReader struct{ data []byte; pos int }
func newBytesReader(b []byte) *bytesReader { return &bytesReader{data: b} }
func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) { return 0, io.EOF }
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
func (r *bytesReader) Close() error { return nil }
