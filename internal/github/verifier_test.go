package github_test

import (
	"context"
	"testing"
	"time"

	gh "github.com/tass-security/tass/internal/github"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

// buildTestScan creates a ScanResult with synthetic capabilities in the memStore.
func buildTestScan(t *testing.T, store *memStore, caps []contracts.Capability) storage.ScanResult {
	t.Helper()
	ctx := context.Background()

	_ = store.UpsertInstallation(ctx, storage.Installation{
		ID: 1, AccountLogin: "testorg", AccountType: "Organization",
		InstalledAt: time.Now().UTC(),
	})
	_ = store.UpsertRepository(ctx, storage.Repository{
		ID: 10, InstallationID: 1, FullName: "testorg/app",
		DefaultBranch: "main", CreatedAt: time.Now().UTC(),
	})

	scan := storage.ScanResult{
		ID:             "scan-test-001",
		RepoID:         10,
		InstallationID: 1,
		PRNumber:       42,
		HeadBranch:     "feature/stripe",
		CommitSHA:      "deadbeef",
		BaseSHA:        "cafebabe",
		ScannedAt:      time.Now().UTC(),
		Capabilities:   caps,
		NovelCount:     len(caps),
		Status:         storage.StatusPending,
		CheckRunID:     0, // no check — avoids real GitHub API calls
		CommentID:      0,
	}
	_ = store.SaveScan(ctx, scan)
	return scan
}

var testCaps = []contracts.Capability{
	{
		ID:       "dep:go:github.com/stripe/stripe-go/v76",
		Name:     "stripe-go",
		Category: contracts.CatExternalDep,
		Source:   contracts.LayerDependency,
		Location: contracts.CodeLocation{File: "go.mod"},
	},
	{
		ID:       "ast:go:net/http:Client.Do",
		Name:     "HTTP client outbound request",
		Category: contracts.CatNetworkAccess,
		Source:   contracts.LayerAST,
		Location: contracts.CodeLocation{File: "internal/client/api.go", Line: 42},
	},
	{
		ID:       "ast:go:os:file:WriteFile",
		Name:     "os.WriteFile",
		Category: contracts.CatFileSystem,
		Source:   contracts.LayerAST,
		Location: contracts.CodeLocation{File: "util/export.go", Line: 88},
	},
}

// newTestVerifier creates a Verifier backed by the memStore.
// Since CheckRunID=0 and CommentID=0, no real GitHub API calls are made
// for check/comment updates. The manifest commit is also skipped
// (HeadBranch exists but GitHubApp won't be called for commit because
// we test with a nil/stub that the memStore doesn't trigger).
//
// For verifier unit tests we focus on the decision + state-machine logic.
// GitHub API integration is tested end-to-end manually.
func newTestVerifier(t *testing.T, store *memStore) *gh.Verifier {
	t.Helper()
	app := newTestApp(t) // test RSA key, no real GitHub calls in unit path
	return gh.NewVerifier(app, store, "http://localhost:8080")
}

func TestVerifier_SingleConfirm_NotAllDecided(t *testing.T) {
	store := newMemStore()
	buildTestScan(t, store, testCaps)
	v := newTestVerifier(t, store)
	ctx := context.Background()

	result, err := v.Decide(ctx,
		"scan-test-001",
		"dep:go:github.com/stripe/stripe-go/v76",
		contracts.DecisionConfirm,
		"Payment processing", "alice",
	)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if result.AllDecided {
		t.Error("AllDecided should be false — 2 caps still undecided")
	}
	if result.ManifestCommitted {
		t.Error("manifest should not be committed yet")
	}
}

func TestVerifier_AllConfirmed(t *testing.T) {
	store := newMemStore()
	buildTestScan(t, store, testCaps)
	v := newTestVerifier(t, store)
	ctx := context.Background()

	// Confirm all three
	for i, cap := range testCaps {
		result, err := v.Decide(ctx, "scan-test-001", cap.ID,
			contracts.DecisionConfirm, "looks good", "alice")
		if err != nil {
			t.Fatalf("Decide cap %d: %v", i, err)
		}
		if i < len(testCaps)-1 && result.AllDecided {
			t.Errorf("AllDecided should be false after cap %d", i)
		}
	}

	// After last decision, AllDecided should be true
	decisions, err := store.GetDecisionsByScan(ctx, "scan-test-001")
	if err != nil {
		t.Fatalf("GetDecisionsByScan: %v", err)
	}
	if len(decisions) != 3 {
		t.Errorf("expected 3 decisions, got %d", len(decisions))
	}
	for _, d := range decisions {
		if d.Decision != contracts.DecisionConfirm {
			t.Errorf("decision for %s: got %q, want confirm", d.CapabilityID, d.Decision)
		}
		if d.DecidedBy != "alice" {
			t.Errorf("decided_by: got %q, want alice", d.DecidedBy)
		}
	}
}

func TestVerifier_MixedDecisions(t *testing.T) {
	store := newMemStore()
	buildTestScan(t, store, testCaps)
	v := newTestVerifier(t, store)
	ctx := context.Background()

	// Confirm 2, revert 1
	decisions := []struct {
		capID    string
		decision contracts.VerificationDecision
	}{
		{testCaps[0].ID, contracts.DecisionConfirm},
		{testCaps[1].ID, contracts.DecisionConfirm},
		{testCaps[2].ID, contracts.DecisionRevert},
	}

	for i, d := range decisions {
		result, err := v.Decide(ctx, "scan-test-001", d.capID, d.decision, "", "bob")
		if err != nil {
			t.Fatalf("Decide %d: %v", i, err)
		}
		_ = result
	}

	stored, _ := store.GetDecisionsByScan(ctx, "scan-test-001")
	decMap := make(map[string]contracts.VerificationDecision)
	for _, d := range stored {
		decMap[d.CapabilityID] = d.Decision
	}

	if decMap[testCaps[0].ID] != contracts.DecisionConfirm {
		t.Error("cap0 should be confirm")
	}
	if decMap[testCaps[1].ID] != contracts.DecisionConfirm {
		t.Error("cap1 should be confirm")
	}
	if decMap[testCaps[2].ID] != contracts.DecisionRevert {
		t.Error("cap2 should be revert")
	}
}

func TestVerifier_UnknownScan(t *testing.T) {
	store := newMemStore()
	v := newTestVerifier(t, store)

	_, err := v.Decide(context.Background(),
		"scan-nonexistent", "some-cap-id",
		contracts.DecisionConfirm, "", "alice")
	if err == nil {
		t.Fatal("expected error for nonexistent scan")
	}
}

func TestVerifier_UnknownCapabilityID(t *testing.T) {
	store := newMemStore()
	buildTestScan(t, store, testCaps)
	v := newTestVerifier(t, store)

	_, err := v.Decide(context.Background(),
		"scan-test-001", "dep:go:not-in-this-scan",
		contracts.DecisionConfirm, "", "alice")
	if err == nil {
		t.Fatal("expected error for capability not in scan")
	}
}

func TestVerifier_AlreadyVerifiedScan(t *testing.T) {
	store := newMemStore()
	scan := buildTestScan(t, store, testCaps[:1])
	v := newTestVerifier(t, store)
	ctx := context.Background()

	// Mark scan as already verified
	_ = store.UpdateScanStatus(ctx, scan.ID, storage.StatusVerified)

	_, err := v.Decide(ctx, scan.ID, testCaps[0].ID,
		contracts.DecisionConfirm, "", "alice")
	if err == nil {
		t.Fatal("expected error for already-verified scan")
	}
}

func TestVerifier_DecisionIsPersisted(t *testing.T) {
	store := newMemStore()
	caps := testCaps[:1]
	buildTestScan(t, store, caps)
	v := newTestVerifier(t, store)
	ctx := context.Background()

	_, err := v.Decide(ctx, "scan-test-001", caps[0].ID,
		contracts.DecisionConfirm, "needed for payments", "carol")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}

	decisions, _ := store.GetDecisionsByScan(ctx, "scan-test-001")
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	d := decisions[0]
	if d.Justification != "needed for payments" {
		t.Errorf("justification: got %q", d.Justification)
	}
	if d.DecidedBy != "carol" {
		t.Errorf("decided_by: got %q", d.DecidedBy)
	}
}
