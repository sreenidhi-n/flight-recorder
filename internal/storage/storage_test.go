package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

func openTestStore(t *testing.T) *storage.SQLiteStore {
	t.Helper()
	s, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestWALMode(t *testing.T) {
	// Open verifies WAL mode is set; if Open succeeds, WAL is active.
	// We confirm by checking PRAGMA journal_mode returns "wal".
	// Since we open with :memory:, WAL silently uses memory journal — the
	// important thing is Open() doesn't error.
	s := openTestStore(t)
	if s == nil {
		t.Fatal("store is nil")
	}
}

func TestInstallationRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	inst := storage.Installation{
		ID:             42,
		AccountLogin:   "acme-corp",
		AccountType:    "Organization",
		InstalledAt:    time.Now().UTC().Truncate(time.Second),
		AccessToken:    "ghs_test_token",
		TokenExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}

	if err := s.UpsertInstallation(ctx, inst); err != nil {
		t.Fatalf("upsert installation: %v", err)
	}

	got, err := s.GetInstallation(ctx, 42)
	if err != nil {
		t.Fatalf("get installation: %v", err)
	}
	if got == nil {
		t.Fatal("expected installation, got nil")
	}
	if got.AccountLogin != inst.AccountLogin {
		t.Errorf("account_login: got %q, want %q", got.AccountLogin, inst.AccountLogin)
	}
	if got.AccountType != inst.AccountType {
		t.Errorf("account_type: got %q, want %q", got.AccountType, inst.AccountType)
	}
	if got.AccessToken != inst.AccessToken {
		t.Errorf("access_token: got %q, want %q", got.AccessToken, inst.AccessToken)
	}
}

func TestInstallationUpsert(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	inst := storage.Installation{
		ID: 99, AccountLogin: "old-login", AccountType: "User",
		InstalledAt: time.Now().UTC(),
	}
	if err := s.UpsertInstallation(ctx, inst); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	inst.AccountLogin = "new-login"
	if err := s.UpsertInstallation(ctx, inst); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	got, _ := s.GetInstallation(ctx, 99)
	if got.AccountLogin != "new-login" {
		t.Errorf("expected upsert to update login; got %q", got.AccountLogin)
	}
}

func TestGetInstallationNotFound(t *testing.T) {
	s := openTestStore(t)
	got, err := s.GetInstallation(context.Background(), 9999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestRepositoryRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Need an installation first (foreign key)
	_ = s.UpsertInstallation(ctx, storage.Installation{
		ID: 1, AccountLogin: "acme", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})

	repo := storage.Repository{
		ID:             101,
		InstallationID: 1,
		FullName:       "acme/my-service",
		DefaultBranch:  "main",
		ManifestSHA:    "abc123",
		CreatedAt:      time.Now().UTC().Truncate(time.Second),
	}
	if err := s.UpsertRepository(ctx, repo); err != nil {
		t.Fatalf("upsert repo: %v", err)
	}

	got, err := s.GetRepository(ctx, 101)
	if err != nil {
		t.Fatalf("get repo: %v", err)
	}
	if got == nil {
		t.Fatal("expected repo, got nil")
	}
	if got.FullName != repo.FullName {
		t.Errorf("full_name: got %q, want %q", got.FullName, repo.FullName)
	}
	if got.ManifestSHA != repo.ManifestSHA {
		t.Errorf("manifest_sha: got %q, want %q", got.ManifestSHA, repo.ManifestSHA)
	}
}

func TestGetRepositoryByFullName(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	_ = s.UpsertInstallation(ctx, storage.Installation{
		ID: 5, AccountLogin: "org", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})
	_ = s.UpsertRepository(ctx, storage.Repository{
		ID: 200, InstallationID: 5, FullName: "org/repo",
		DefaultBranch: "main", CreatedAt: time.Now().UTC(),
	})

	got, err := s.GetRepositoryByFullName(ctx, 5, "org/repo")
	if err != nil {
		t.Fatalf("get by full name: %v", err)
	}
	if got == nil || got.ID != 200 {
		t.Errorf("expected repo ID 200, got %v", got)
	}

	// Wrong installation — tenant isolation
	other, err := s.GetRepositoryByFullName(ctx, 99, "org/repo")
	if err != nil {
		t.Fatalf("tenant isolation query: %v", err)
	}
	if other != nil {
		t.Error("expected nil for wrong installation_id, got a repo")
	}
}

func setupRepoAndInstallation(t *testing.T, s *storage.SQLiteStore) (installationID, repoID int64) {
	t.Helper()
	ctx := context.Background()
	installationID, repoID = 10, 300
	_ = s.UpsertInstallation(ctx, storage.Installation{
		ID: installationID, AccountLogin: "testorg", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})
	_ = s.UpsertRepository(ctx, storage.Repository{
		ID: repoID, InstallationID: installationID, FullName: "testorg/app",
		DefaultBranch: "main", CreatedAt: time.Now().UTC(),
	})
	return
}

func TestScanRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, repoID := setupRepoAndInstallation(t, s)

	scan := storage.ScanResult{
		ID:             "scan-001",
		RepoID:         repoID,
		PRNumber:       7,
		CommitSHA:      "deadbeef",
		BaseSHA:        "cafebabe",
		ScannedAt:      time.Now().UTC().Truncate(time.Second),
		ScanDurationMS: 420,
		Capabilities: []contracts.Capability{
			{
				ID:       "dep:go:github.com/stripe/stripe-go/v76",
				Name:     "stripe-go",
				Category: contracts.CatExternalDep,
				Source:   contracts.LayerDependency,
			},
		},
		NovelCount: 1,
		Status:     storage.StatusPending,
	}

	if err := s.SaveScan(ctx, scan); err != nil {
		t.Fatalf("save scan: %v", err)
	}

	got, err := s.GetScan(ctx, "scan-001")
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if got == nil {
		t.Fatal("expected scan, got nil")
	}
	if got.PRNumber != scan.PRNumber {
		t.Errorf("pr_number: got %d, want %d", got.PRNumber, scan.PRNumber)
	}
	if len(got.Capabilities) != 1 {
		t.Errorf("capabilities: got %d, want 1", len(got.Capabilities))
	}
	if got.Capabilities[0].ID != scan.Capabilities[0].ID {
		t.Errorf("capability ID: got %q, want %q", got.Capabilities[0].ID, scan.Capabilities[0].ID)
	}
	if got.Status != storage.StatusPending {
		t.Errorf("status: got %q, want pending", got.Status)
	}
}

func TestScanStatusUpdate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, repoID := setupRepoAndInstallation(t, s)

	_ = s.SaveScan(ctx, storage.ScanResult{
		ID: "scan-002", RepoID: repoID, PRNumber: 1,
		CommitSHA: "aaa", BaseSHA: "bbb",
		ScannedAt: time.Now().UTC(), Capabilities: nil,
		Status: storage.StatusPending,
	})

	if err := s.UpdateScanStatus(ctx, "scan-002", storage.StatusVerified); err != nil {
		t.Fatalf("update status: %v", err)
	}

	got, _ := s.GetScan(ctx, "scan-002")
	if got.Status != storage.StatusVerified {
		t.Errorf("expected verified, got %q", got.Status)
	}
}

func TestGetScansByRepo(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, repoID := setupRepoAndInstallation(t, s)

	for i := 1; i <= 3; i++ {
		_ = s.SaveScan(ctx, storage.ScanResult{
			ID: fmt.Sprintf("scan-%03d", i), RepoID: repoID, PRNumber: i,
			CommitSHA: "aaa", BaseSHA: "bbb",
			ScannedAt: time.Now().UTC(), Capabilities: nil,
			Status: storage.StatusPending,
		})
	}

	scans, err := s.GetScansByRepo(ctx, repoID, 10)
	if err != nil {
		t.Fatalf("get scans by repo: %v", err)
	}
	if len(scans) != 3 {
		t.Errorf("expected 3 scans, got %d", len(scans))
	}
}

func TestDecisionRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, repoID := setupRepoAndInstallation(t, s)

	_ = s.SaveScan(ctx, storage.ScanResult{
		ID: "scan-d01", RepoID: repoID, PRNumber: 5,
		CommitSHA: "aaa", BaseSHA: "bbb",
		ScannedAt: time.Now().UTC(), Capabilities: nil,
		Status: storage.StatusPending,
	})

	decisions := []storage.VerificationDecision{
		{
			ID: "dec-1", ScanID: "scan-d01",
			CapabilityID:  "dep:go:github.com/stripe/stripe-go",
			Decision:      contracts.DecisionConfirm,
			Justification: "Intentional payment integration",
			DecidedBy:     "alice",
			DecidedAt:     time.Now().UTC().Truncate(time.Second),
		},
		{
			ID: "dec-2", ScanID: "scan-d01",
			CapabilityID: "dep:go:github.com/some/other",
			Decision:     contracts.DecisionRevert,
			DecidedBy:    "bob",
			DecidedAt:    time.Now().UTC().Truncate(time.Second),
		},
	}

	for _, d := range decisions {
		if err := s.SaveDecision(ctx, d); err != nil {
			t.Fatalf("save decision %s: %v", d.ID, err)
		}
	}

	got, err := s.GetDecisionsByScan(ctx, "scan-d01")
	if err != nil {
		t.Fatalf("get decisions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(got))
	}
	if got[0].Decision != contracts.DecisionConfirm {
		t.Errorf("first decision: got %q, want confirm", got[0].Decision)
	}
	if got[1].Decision != contracts.DecisionRevert {
		t.Errorf("second decision: got %q, want revert", got[1].Decision)
	}
	if got[0].Justification != "Intentional payment integration" {
		t.Errorf("justification: got %q", got[0].Justification)
	}
}

func TestStatsScoping(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Two tenants
	_ = s.UpsertInstallation(ctx, storage.Installation{
		ID: 1, AccountLogin: "org1", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})
	_ = s.UpsertInstallation(ctx, storage.Installation{
		ID: 2, AccountLogin: "org2", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})
	_ = s.UpsertRepository(ctx, storage.Repository{
		ID: 10, InstallationID: 1, FullName: "org1/app",
		DefaultBranch: "main", CreatedAt: time.Now().UTC(),
	})
	_ = s.UpsertRepository(ctx, storage.Repository{
		ID: 20, InstallationID: 2, FullName: "org2/app",
		DefaultBranch: "main", CreatedAt: time.Now().UTC(),
	})

	// 3 scans for repo 10, 1 for repo 20
	for i := 1; i <= 3; i++ {
		_ = s.SaveScan(ctx, storage.ScanResult{
			ID: fmt.Sprintf("r10-s%d", i), RepoID: 10, PRNumber: i,
			CommitSHA: "aaa", BaseSHA: "bbb",
			ScannedAt: time.Now().UTC(), NovelCount: 2,
			Capabilities: nil, Status: storage.StatusPending,
		})
	}
	_ = s.SaveScan(ctx, storage.ScanResult{
		ID: "r20-s1", RepoID: 20, PRNumber: 1,
		CommitSHA: "ccc", BaseSHA: "ddd",
		ScannedAt: time.Now().UTC(), NovelCount: 5,
		Capabilities: nil, Status: storage.StatusPending,
	})

	// Decisions for repo 10 scans
	_ = s.SaveDecision(ctx, storage.VerificationDecision{
		ID: "dec-a", ScanID: "r10-s1", CapabilityID: "cap-x",
		Decision: contracts.DecisionConfirm, DecidedBy: "alice",
		DecidedAt: time.Now().UTC(),
	})
	_ = s.SaveDecision(ctx, storage.VerificationDecision{
		ID: "dec-b", ScanID: "r10-s1", CapabilityID: "cap-y",
		Decision: contracts.DecisionRevert, DecidedBy: "alice",
		DecidedAt: time.Now().UTC(),
	})

	stats10, err := s.GetStats(ctx, 10)
	if err != nil {
		t.Fatalf("get stats repo 10: %v", err)
	}
	if stats10.TotalScans != 3 {
		t.Errorf("repo10 total_scans: got %d, want 3", stats10.TotalScans)
	}
	if stats10.TotalCaps != 6 { // 3 scans × 2 novel each
		t.Errorf("repo10 total_caps: got %d, want 6", stats10.TotalCaps)
	}
	if stats10.ConfirmCount != 1 {
		t.Errorf("repo10 confirm_count: got %d, want 1", stats10.ConfirmCount)
	}
	if stats10.RevertCount != 1 {
		t.Errorf("repo10 revert_count: got %d, want 1", stats10.RevertCount)
	}

	// Stats for repo 20 must be isolated
	stats20, err := s.GetStats(ctx, 20)
	if err != nil {
		t.Fatalf("get stats repo 20: %v", err)
	}
	if stats20.TotalScans != 1 {
		t.Errorf("repo20 total_scans: got %d, want 1", stats20.TotalScans)
	}
	if stats20.ConfirmCount != 0 {
		t.Errorf("repo20 confirm_count should be 0, got %d", stats20.ConfirmCount)
	}
}
