// Package e2e contains end-to-end tests for the TASS platform.
// These tests spin up a mock GitHub API server and run the full
// webhook → scan → store → verify → commit → check-green flow in-process.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/internal/server"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

// --- Mock GitHub API ---

// mockGitHub tracks calls made to the mock server so the test can assert them.
type mockGitHub struct {
	mu sync.Mutex

	checkRunCreated int
	checkRunUpdates int
	commentCreated  int
	commentUpdated  int
	manifestPut     int

	lastManifestContent []byte
	lastCheckConclusion string
}

func newMockGitHubServer(t *testing.T, m *mockGitHub) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Installation token exchange (GitHub returns 201 Created)
	mux.HandleFunc("/app/installations/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/access_tokens") {
			exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":"ghs_testtoken","expires_at":%q}`, exp)
			return
		}
		http.NotFound(w, r)
	})

	// Check run create
	mux.HandleFunc("/repos/testorg/testrepo/check-runs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		m.mu.Lock()
		m.checkRunCreated++
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":42}`)
	})

	// Check run update
	mux.HandleFunc("/repos/testorg/testrepo/check-runs/42", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload) //nolint:errcheck
		m.mu.Lock()
		m.checkRunUpdates++
		if c, ok := payload["conclusion"].(string); ok {
			m.lastCheckConclusion = c
		}
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{}`)
	})

	// PR files list
	mux.HandleFunc("/repos/testorg/testrepo/pulls/7/files", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"filename":"requirements.txt","status":"modified"}]`)
	})

	// File contents + manifest commit (PUT)
	mux.HandleFunc("/repos/testorg/testrepo/contents/", func(w http.ResponseWriter, r *http.Request) {
		ref := r.URL.Query().Get("ref")
		path := strings.TrimPrefix(r.URL.Path, "/repos/testorg/testrepo/contents/")

		if r.Method == http.MethodPut && path == "tass.manifest.yaml" {
			var payload map[string]any
			json.NewDecoder(r.Body).Decode(&payload) //nolint:errcheck
			m.mu.Lock()
			m.manifestPut++
			if content, ok := payload["content"].(string); ok {
				decoded, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
				m.lastManifestContent = decoded
			}
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"commit":{"sha":"commit-abc123"}}`)
			return
		}

		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}

		switch path {
		case "requirements.txt":
			if ref == "headsha001" {
				content := base64.StdEncoding.EncodeToString([]byte("requests==2.31.0\n"))
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"content":%q,"encoding":"base64","sha":"blob-req-sha"}`, content)
			} else {
				// Base version doesn't exist → new dependency
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `{"message":"Not Found"}`)
			}
		case "tass.manifest.yaml":
			// No manifest yet on any ref
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"message":"Not Found"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"message":"Not Found"}`)
		}
	})

	// PR comments list + create
	mux.HandleFunc("/repos/testorg/testrepo/issues/7/comments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			fmt.Fprintf(w, `[]`)
		case http.MethodPost:
			m.mu.Lock()
			m.commentCreated++
			m.mu.Unlock()
			fmt.Fprintf(w, `{"id":99}`)
		default:
			http.NotFound(w, r)
		}
	})

	// Comment update
	mux.HandleFunc("/repos/testorg/testrepo/issues/comments/99", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		m.mu.Lock()
		m.commentUpdated++
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":99}`)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// --- Test helpers ---

// generateTestKeyFile creates a fresh RSA key in a temp dir and returns the path.
func generateTestKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})

	path := t.TempDir() + "/test.pem"
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

func buildTestApp(t *testing.T, apiBaseURL string) *gh.App {
	t.Helper()
	cfg := gh.Config{
		AppID:          12345,
		WebhookSecret:  "test-secret",
		PrivateKeyPath: generateTestKeyFile(t),
		APIBaseURL:     apiBaseURL,
	}
	app, err := gh.NewApp(cfg)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return app
}

// standardScanRequest returns a ScanRequest that exercises the mock server.
func standardScanRequest(repoID int64) gh.ScanRequest {
	return gh.ScanRequest{
		InstallationID: 99,
		RepoID:         repoID,
		RepoFullName:   "testorg/testrepo",
		PRNumber:       7,
		HeadSHA:        "headsha001",
		BaseSHA:        "basesha000001",
		HeadBranch:     "feat/add-requests",
		BaseBranch:     "main",
	}
}

// --- Tests ---

// TestPhase3_FullFlow is the Phase 3 integration test.
// It exercises the complete platform flow: scan → store → verify → commit → check green.
func TestPhase3_FullFlow(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitHub{}
	mockSrv := newMockGitHubServer(t, mock)

	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	app := buildTestApp(t, mockSrv.URL)
	sc := scanner.New(scanner.DefaultRegistry, nil) // Layer 1 disabled: no rules dir in e2e
	pipeline := gh.NewPipeline(app, sc, store, "http://localhost:8080")
	verifier := gh.NewVerifier(app, store, "http://localhost:8080")

	req := standardScanRequest(1001)

	// ── Phase 1: Run the scan pipeline ──────────────────────────────────────
	pipeline.Run(ctx, req)

	scanID := fmt.Sprintf("scan-testorg-testrepo-%d-%s", req.PRNumber, req.HeadSHA[:8])
	scan, err := store.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan == nil {
		t.Fatal("expected scan to be stored, got nil")
	}
	if scan.NovelCount == 0 {
		t.Fatal("expected ≥1 novel capability to be detected (requirements.txt with requests==2.31.0)")
	}
	t.Logf("scan stored: id=%s novel_count=%d", scan.ID, scan.NovelCount)

	mock.mu.Lock()
	gotCheckCreate := mock.checkRunCreated
	gotCommentCreate := mock.commentCreated
	mock.mu.Unlock()
	if gotCheckCreate != 1 {
		t.Errorf("check run created: want 1, got %d", gotCheckCreate)
	}
	if gotCommentCreate != 1 {
		t.Errorf("PR comment created: want 1, got %d", gotCommentCreate)
	}

	// ── Phase 2: Verify all capabilities (confirm) ───────────────────────────
	for _, cap := range scan.Capabilities {
		result, err := verifier.Decide(ctx, scanID, cap.ID, contracts.DecisionConfirm, "intentional", "alice@example.com")
		if err != nil {
			t.Fatalf("Decide cap=%s: %v", cap.ID, err)
		}
		t.Logf("decided cap=%s all_decided=%v manifest_committed=%v check_updated=%v",
			cap.ID, result.AllDecided, result.ManifestCommitted, result.CheckUpdated)
	}

	// ── Phase 3: Assert post-verification state ──────────────────────────────
	finalScan, err := store.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("get final scan: %v", err)
	}
	if finalScan.Status != storage.StatusVerified {
		t.Errorf("scan status: want verified, got %s", finalScan.Status)
	}

	mock.mu.Lock()
	gotManifestPut := mock.manifestPut
	gotManifestContent := string(mock.lastManifestContent)
	gotConclusion := mock.lastCheckConclusion
	gotCommentUpdate := mock.commentUpdated
	mock.mu.Unlock()

	if gotManifestPut == 0 {
		t.Error("manifest PUT: expected ≥1, got 0")
	}
	if !strings.Contains(gotManifestContent, "confirmed") {
		t.Errorf("manifest content should contain 'confirmed', got: %s", gotManifestContent)
	}
	if gotConclusion != string(gh.ConclusionSuccess) {
		t.Errorf("check conclusion: want success, got %q", gotConclusion)
	}
	if gotCommentUpdate == 0 {
		t.Error("PR comment update: expected ≥1, got 0")
	}

	// ── Phase 4: Verify analytics ────────────────────────────────────────────
	stats, err := store.GetStats(ctx, req.RepoID)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalScans != 1 {
		t.Errorf("stats total_scans: want 1, got %d", stats.TotalScans)
	}
	if stats.ConfirmCount != scan.NovelCount {
		t.Errorf("stats confirm_count: want %d, got %d", scan.NovelCount, stats.ConfirmCount)
	}
	if stats.RevertCount != 0 {
		t.Errorf("stats revert_count: want 0, got %d", stats.RevertCount)
	}
	if len(stats.ByDeveloper) == 0 {
		t.Error("stats ByDeveloper: expected entries")
	}
	t.Logf("stats: total_scans=%d confirms=%d reverts=%d developers=%v",
		stats.TotalScans, stats.ConfirmCount, stats.RevertCount, stats.ByDeveloper)

	// ── Phase 5: Stats HTTP endpoint ─────────────────────────────────────────
	statsH := server.NewStatsHandler(store)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/stats?repo_id=%d", req.RepoID), nil)
	statsH.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("stats endpoint: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var statsResp storage.RepoStats
	if err := json.NewDecoder(w.Body).Decode(&statsResp); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if statsResp.TotalScans != 1 {
		t.Errorf("stats endpoint total_scans: want 1, got %d", statsResp.TotalScans)
	}

	t.Log("✓ Phase 3 integration test: PASS — full webhook→scan→verify→manifest→check flow")
}

// TestPhase3_AllReverts verifies that a revert leads to action_required check conclusion.
func TestPhase3_AllReverts(t *testing.T) {
	ctx := context.Background()
	mock := &mockGitHub{}
	mockSrv := newMockGitHubServer(t, mock)

	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	app := buildTestApp(t, mockSrv.URL)
	sc := scanner.New(scanner.DefaultRegistry, nil)
	pipeline := gh.NewPipeline(app, sc, store, "http://localhost:8080")
	verifier := gh.NewVerifier(app, store, "http://localhost:8080")

	req := standardScanRequest(2002)
	pipeline.Run(ctx, req)

	scanID := fmt.Sprintf("scan-testorg-testrepo-%d-%s", req.PRNumber, req.HeadSHA[:8])
	scan, err := store.GetScan(ctx, scanID)
	if err != nil || scan == nil {
		t.Fatalf("get scan: err=%v scan=%v", err, scan)
	}
	if scan.NovelCount == 0 {
		t.Skip("no capabilities detected — skipping revert test")
	}

	// Revert all capabilities
	for _, cap := range scan.Capabilities {
		if _, err := verifier.Decide(ctx, scanID, cap.ID, contracts.DecisionRevert, "unintended", "bob@example.com"); err != nil {
			t.Fatalf("Decide revert cap=%s: %v", cap.ID, err)
		}
	}

	mock.mu.Lock()
	conclusion := mock.lastCheckConclusion
	mock.mu.Unlock()

	if conclusion != string(gh.ConclusionActionRequired) {
		t.Errorf("check conclusion: want action_required for all-revert, got %q", conclusion)
	}
	t.Logf("✓ all-reverts test: check conclusion=%s", conclusion)
}
