package github_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/storage"
)

// --- minimal in-memory store for handler tests ---

type memStore struct {
	installations map[int64]storage.Installation
}

func newMemStore() *memStore {
	return &memStore{installations: make(map[int64]storage.Installation)}
}

func (m *memStore) UpsertInstallation(_ context.Context, inst storage.Installation) error {
	m.installations[inst.ID] = inst
	return nil
}
func (m *memStore) GetInstallation(_ context.Context, id int64) (*storage.Installation, error) {
	if i, ok := m.installations[id]; ok {
		return &i, nil
	}
	return nil, nil
}
func (m *memStore) UpsertRepository(_ context.Context, _ storage.Repository) error { return nil }
func (m *memStore) GetRepository(_ context.Context, _ int64) (*storage.Repository, error) {
	return nil, nil
}
func (m *memStore) GetRepositoryByFullName(_ context.Context, _ int64, _ string) (*storage.Repository, error) {
	return nil, nil
}
func (m *memStore) UpdateManifestSHA(_ context.Context, _ int64, _ string) error { return nil }
func (m *memStore) SaveScan(_ context.Context, _ storage.ScanResult) error        { return nil }
func (m *memStore) GetScan(_ context.Context, _ string) (*storage.ScanResult, error) {
	return nil, nil
}
func (m *memStore) GetScansByRepo(_ context.Context, _ int64, _ int) ([]storage.ScanResult, error) {
	return nil, nil
}
func (m *memStore) UpdateScanStatus(_ context.Context, _ string, _ storage.ScanStatus) error {
	return nil
}
func (m *memStore) SaveDecision(_ context.Context, _ storage.VerificationDecision) error { return nil }
func (m *memStore) GetDecisionsByScan(_ context.Context, _ string) ([]storage.VerificationDecision, error) {
	return nil, nil
}
func (m *memStore) GetStats(_ context.Context, _ int64) (*storage.RepoStats, error) { return nil, nil }
func (m *memStore) Close() error                                                      { return nil }

// --- helpers ---

func signPayload(t *testing.T, secret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func newHandlerWithCapture(t *testing.T) (*gh.Handler, *memStore, chan gh.ScanRequest) {
	t.Helper()
	app := newTestApp(t)
	store := newMemStore()
	received := make(chan gh.ScanRequest, 4)
	onScan := func(_ context.Context, req gh.ScanRequest) {
		received <- req
	}
	h := gh.NewHandler(app, store, onScan)
	return h, store, received
}

func postWebhook(t *testing.T, handler http.Handler, eventType string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := signPayload(t, "test-webhook-secret", body)

	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", eventType)
	req.Header.Set("X-GitHub-Delivery", "test-delivery-001")
	req.Header.Set("X-Hub-Signature-256", sig)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// --- tests ---

func TestHandler_RejectsInvalidSignature(t *testing.T) {
	h := gh.NewHandler(newTestApp(t), newMemStore(), nil)

	body := []byte(`{"action":"opened"}`)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", bytes.NewReader(body))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=badbadbad")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandler_RejectsNonPost(t *testing.T) {
	h := gh.NewHandler(newTestApp(t), newMemStore(), nil)
	req := httptest.NewRequest(http.MethodGet, "/webhooks/github", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandler_PullRequestOpened(t *testing.T) {
	h, _, received := newHandlerWithCapture(t)

	payload := map[string]any{
		"action": "opened",
		"number": 42,
		"pull_request": map[string]any{
			"number": 42,
			"head": map[string]any{
				"sha": "deadbeef",
				"ref": "feature/stripe",
				"repo": map[string]any{"id": 999, "full_name": "acme/app", "private": false},
			},
			"base": map[string]any{
				"sha": "cafebabe",
				"ref": "main",
				"repo": map[string]any{"id": 999, "full_name": "acme/app", "private": false},
			},
		},
		"repository": map[string]any{
			"id":             999,
			"full_name":      "acme/app",
			"private":        false,
			"default_branch": "main",
		},
		"installation": map[string]any{"id": 12345},
	}

	rr := postWebhook(t, h, "pull_request", payload)

	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}

	// Wait for the background goroutine to fire
	select {
	case req := <-received:
		if req.PRNumber != 42 {
			t.Errorf("PRNumber: got %d, want 42", req.PRNumber)
		}
		if req.HeadSHA != "deadbeef" {
			t.Errorf("HeadSHA: got %q, want deadbeef", req.HeadSHA)
		}
		if req.BaseSHA != "cafebabe" {
			t.Errorf("BaseSHA: got %q, want cafebabe", req.BaseSHA)
		}
		if req.RepoFullName != "acme/app" {
			t.Errorf("RepoFullName: got %q, want acme/app", req.RepoFullName)
		}
		if req.InstallationID != 12345 {
			t.Errorf("InstallationID: got %d, want 12345", req.InstallationID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scan request")
	}
}

func TestHandler_PullRequestSynchronize(t *testing.T) {
	h, _, received := newHandlerWithCapture(t)

	payload := map[string]any{
		"action": "synchronize",
		"number": 7,
		"pull_request": map[string]any{
			"number": 7,
			"head":   map[string]any{"sha": "aaa111", "ref": "feat/x", "repo": map[string]any{"id": 1, "full_name": "org/r"}},
			"base":   map[string]any{"sha": "bbb222", "ref": "main", "repo": map[string]any{"id": 1, "full_name": "org/r"}},
		},
		"repository": map[string]any{"id": 1, "full_name": "org/r", "private": false, "default_branch": "main"},
		"installation": map[string]any{"id": 55},
	}

	rr := postWebhook(t, h, "pull_request", payload)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}

	select {
	case req := <-received:
		if req.PRNumber != 7 {
			t.Errorf("PRNumber: got %d, want 7", req.PRNumber)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scan request")
	}
}

func TestHandler_PullRequestClosed_Ignored(t *testing.T) {
	h, _, received := newHandlerWithCapture(t)

	payload := map[string]any{
		"action": "closed",
		"number": 1,
		"pull_request": map[string]any{
			"number": 1,
			"head":   map[string]any{"sha": "aaa", "ref": "feat", "repo": map[string]any{"id": 1, "full_name": "o/r"}},
			"base":   map[string]any{"sha": "bbb", "ref": "main", "repo": map[string]any{"id": 1, "full_name": "o/r"}},
		},
		"repository": map[string]any{"id": 1, "full_name": "o/r", "private": false, "default_branch": "main"},
	}

	rr := postWebhook(t, h, "pull_request", payload)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}

	// Must NOT trigger a scan
	select {
	case req := <-received:
		t.Errorf("expected no scan for closed PR, got %+v", req)
	case <-time.After(200 * time.Millisecond):
		// good — nothing fired
	}
}

func TestHandler_InstallationCreated(t *testing.T) {
	h, store, _ := newHandlerWithCapture(t)

	payload := map[string]any{
		"action": "created",
		"installation": map[string]any{
			"id": 99887,
			"account": map[string]any{
				"login": "some-org",
				"type":  "Organization",
			},
		},
	}

	rr := postWebhook(t, h, "installation", payload)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}

	// Give the goroutine time to store the installation
	time.Sleep(100 * time.Millisecond)

	inst, err := store.GetInstallation(context.Background(), 99887)
	if err != nil {
		t.Fatalf("get installation: %v", err)
	}
	if inst == nil {
		t.Fatal("expected installation to be stored, got nil")
	}
	if inst.AccountLogin != "some-org" {
		t.Errorf("AccountLogin: got %q, want some-org", inst.AccountLogin)
	}
	if inst.AccountType != "Organization" {
		t.Errorf("AccountType: got %q, want Organization", inst.AccountType)
	}
}

func TestHandler_UnknownEvent_Accepted(t *testing.T) {
	h := gh.NewHandler(newTestApp(t), newMemStore(), nil)
	payload := map[string]any{"zen": "Keep it logically awesome."}
	rr := postWebhook(t, h, "ping", payload)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202 for unknown event, got %d", rr.Code)
	}
}
