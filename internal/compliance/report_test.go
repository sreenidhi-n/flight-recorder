package compliance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tass-security/tass/internal/audit"
	"github.com/tass-security/tass/internal/compliance"
	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

// --- TestControlIDs: verify mapping for every category ---

func TestControlIDs(t *testing.T) {
	cases := []struct {
		cat      contracts.CapCategory
		fw       string
		wantSome bool
	}{
		{contracts.CatNetworkAccess, "soc2", true},
		{contracts.CatNetworkAccess, "iso27001", true},
		{contracts.CatNetworkAccess, "nist80053", true},
		{contracts.CatExternalDep, "soc2", true},
		{contracts.CatDatabaseOp, "nist80053", true},
		{contracts.CatFileSystem, "iso27001", true},
		{contracts.CatPrivilege, "soc2", true},
		{contracts.CatExternalAPI, "nist80053", true},
	}
	for _, tc := range cases {
		ids := compliance.ControlIDs(tc.cat, tc.fw)
		if tc.wantSome && len(ids) == 0 {
			t.Errorf("ControlIDs(%s, %s) = empty, want non-empty", tc.cat, tc.fw)
		}
		// IDs must be non-empty strings.
		for _, id := range ids {
			if id == "" {
				t.Errorf("ControlIDs(%s, %s) contains empty ID", tc.cat, tc.fw)
			}
		}
	}
}

// --- TestFrameworksLoad: YAML parses without panic ---

func TestFrameworksLoad(t *testing.T) {
	f := compliance.Load()
	if len(f.Frameworks) == 0 {
		t.Fatal("Load(): no frameworks parsed")
	}
	if f.Frameworks["soc2"].Name == "" {
		t.Error("soc2 framework name is empty")
	}
	if len(f.CityMappings) == 0 {
		t.Fatal("Load(): no city_mappings parsed")
	}
	if len(f.TassControls) == 0 {
		t.Fatal("Load(): no tass_product_controls parsed")
	}
}

// --- TestGenerate: basic report generation ---

func TestGenerate(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	report, err := gen.Generate(context.Background(), "owner/repo", "soc2", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if report.Data.Repo != "owner/repo" {
		t.Errorf("Repo = %q, want %q", report.Data.Repo, "owner/repo")
	}
	if report.ReportHash == "" {
		t.Error("ReportHash is empty")
	}
	if report.Data.Summary.TotalCapabilities == 0 {
		t.Error("expected non-zero capabilities")
	}
	// At least one control ID should be mapped.
	if len(report.Data.ControlMatrix) == 0 {
		t.Error("control matrix is empty")
	}
}

// --- TestGenerateDeterministic: same input → same hash ---

func TestGenerateDeterministic(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	r1, err := gen.Generate(context.Background(), "owner/repo", "soc2", nil)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := gen.Generate(context.Background(), "owner/repo", "soc2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ReportHash != r2.ReportHash {
		t.Errorf("hash not deterministic: %s vs %s", r1.ReportHash, r2.ReportHash)
	}
}

// --- TestGenerateChainBroken: broken chain returns ErrChainBroken ---

func TestGenerateChainBroken(t *testing.T) {
	store := newTestStore()
	store.brokenChain = true
	gen := compliance.NewGenerator(store, "test")

	report, err := gen.Generate(context.Background(), "owner/repo", "soc2", nil)
	if !errors.Is(err, compliance.ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken, got: %v", err)
	}
	// Report is still returned with chain attestation showing failure.
	if report == nil {
		t.Fatal("report should not be nil even when chain broken")
	}
	if report.Data.ChainAttestation.OK {
		t.Error("ChainAttestation.OK should be false when chain broken")
	}
	// Markdown must prominently indicate failure.
	md := report.ToMarkdown()
	if !containsAny(md, "AUDIT CHAIN INTEGRITY FAILURE", "BROKEN") {
		t.Error("Markdown does not prominently flag broken chain")
	}
}

// --- TestToJSON: output is valid parseable JSON ---

func TestToJSON(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	report, _ := gen.Generate(context.Background(), "owner/repo", "all", nil)
	b, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("JSON output is not valid: %v\noutput: %s", err, b[:min(200, len(b))])
	}
}

// --- TestToPDF: produces non-empty PDF under 500KB ---

func TestToPDF(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	report, _ := gen.Generate(context.Background(), "owner/repo", "nist80053", nil)
	pdf, err := report.ToPDF()
	if err != nil {
		t.Fatalf("ToPDF: %v", err)
	}
	if len(pdf) == 0 {
		t.Fatal("PDF is empty")
	}
	if len(pdf) > 500*1024 {
		t.Errorf("PDF size %d bytes exceeds 500KB limit", len(pdf))
	}
	// Must start with PDF magic bytes.
	if string(pdf[:7]) != "%PDF-1." {
		t.Errorf("PDF magic bytes wrong: %q", pdf[:7])
	}
}

// --- TestToMarkdown: contains required sections ---

func TestToMarkdown(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	report, _ := gen.Generate(context.Background(), "owner/repo", "iso27001", nil)
	md := report.ToMarkdown()

	required := []string{
		"Executive Summary",
		"Detected Capabilities",
		"Control Coverage Matrix",
		"Residual Risk",
		"TASS Product Controls",
		"Audit Chain Attestation",
		"Framework Versions",
		report.ReportHash,
	}
	for _, want := range required {
		if !containsAny(md, want) {
			t.Errorf("Markdown missing expected content: %q", want)
		}
	}
}

// --- TestRepoNotFound ---

func TestRepoNotFound(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	_, err := gen.Generate(context.Background(), "owner/no-such-repo", "soc2", nil)
	if err == nil {
		t.Fatal("expected error for unknown repo")
	}
}

// --- TestSinceFilter ---

func TestSinceFilter(t *testing.T) {
	store := newTestStore()
	gen := compliance.NewGenerator(store, "test")

	// Use a future time to filter out all scans.
	future := time.Now().Add(24 * time.Hour)
	report, err := gen.Generate(context.Background(), "owner/repo", "soc2", &future)
	if err != nil {
		t.Fatalf("Generate with since filter: %v", err)
	}
	if report.Data.Summary.TotalScans != 0 {
		t.Errorf("since filter: expected 0 scans, got %d", report.Data.Summary.TotalScans)
	}
}

// --- helpers ---

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- testStore: in-memory Store for tests ---

type testStore struct {
	repos       map[string]*storage.Repository
	scans       map[int64][]storage.ScanResult
	decisions   map[string][]storage.VerificationDecision
	chainRows   []storage.AuditChainRow
	brokenChain bool
}

func newTestStore() *testStore {
	ts := &testStore{
		repos:     map[string]*storage.Repository{},
		scans:     map[int64][]storage.ScanResult{},
		decisions: map[string][]storage.VerificationDecision{},
	}

	// Seed a repository.
	ts.repos["owner/repo"] = &storage.Repository{
		ID:             1,
		InstallationID: 10,
		FullName:       "owner/repo",
		DefaultBranch:  "main",
	}

	// Seed 5 scans each with one capability from a different category.
	categories := []contracts.CapCategory{
		contracts.CatNetworkAccess,
		contracts.CatExternalDep,
		contracts.CatDatabaseOp,
		contracts.CatFileSystem,
		contracts.CatPrivilege,
	}
	for i, cat := range categories {
		scanID := fmt.Sprintf("scan-%d", i)
		cap := contracts.Capability{
			ID:       fmt.Sprintf("cap-%d", i),
			Name:     fmt.Sprintf("Test capability %d", i),
			Category: cat,
			Source:   contracts.LayerAST,
		}
		ts.scans[1] = append(ts.scans[1], storage.ScanResult{
			ID:         scanID,
			RepoID:     1,
			ScannedAt:  time.Now().Add(-time.Duration(i) * time.Hour),
			Capabilities: []contracts.Capability{cap},
			NovelCount: 1,
			Status:     storage.StatusVerified,
		})
		// Mark all as confirmed.
		ts.decisions[scanID] = []storage.VerificationDecision{{
			ScanID:       scanID,
			CapabilityID: cap.ID,
			Decision:     contracts.DecisionConfirm,
			DecidedBy:    "alice",
			DecidedAt:    time.Now(),
		}}
	}

	// Build a valid hash chain with 3 events.
	prevHash := ""
	for i := 0; i < 3; i++ {
		row := storage.AuditChainRow{
			ID:       fmt.Sprintf("evt-%d", i),
			Ts:       time.Now().Add(-time.Duration(i) * time.Minute).UTC().Format(time.RFC3339Nano),
			TenantID: 10,
			Action:   "capability_confirmed",
			PrevHash: prevHash,
		}
		input := audit.HashInput{
			ID:       row.ID,
			Ts:       row.Ts,
			TenantID: row.TenantID,
			Action:   row.Action,
			PrevHash: prevHash,
		}
		h, _ := audit.ComputeHash(prevHash, input)
		row.Hash = h
		prevHash = h
		ts.chainRows = append(ts.chainRows, row)
	}

	return ts
}

// Store interface implementation.

func (s *testStore) FindRepoByName(_ context.Context, name string) (*storage.Repository, error) {
	r, ok := s.repos[name]
	if !ok {
		return nil, nil
	}
	return r, nil
}
func (s *testStore) GetScansByRepo(_ context.Context, repoID int64, limit int) ([]storage.ScanResult, error) {
	scans := s.scans[repoID]
	if len(scans) > limit {
		scans = scans[:limit]
	}
	return scans, nil
}
func (s *testStore) GetDecisionsByScan(_ context.Context, scanID string) ([]storage.VerificationDecision, error) {
	return s.decisions[scanID], nil
}
func (s *testStore) GetAuditChainRows(_ context.Context, _ int64) ([]storage.AuditChainRow, error) {
	if s.brokenChain {
		// Return rows with wrong hashes to simulate tampering.
		rows := make([]storage.AuditChainRow, len(s.chainRows))
		copy(rows, s.chainRows)
		if len(rows) > 0 {
			rows[0].Hash = "deadbeef"
		}
		return rows, nil
	}
	return s.chainRows, nil
}

// Unused Store methods — no-op stubs satisfying the interface.
func (s *testStore) UpsertInstallation(_ context.Context, _ storage.Installation) error { return nil }
func (s *testStore) GetInstallation(_ context.Context, _ int64) (*storage.Installation, error) {
	return nil, nil
}
func (s *testStore) GetInstallationByLogin(_ context.Context, _ string) (*storage.Installation, error) {
	return nil, nil
}
func (s *testStore) UpsertRepository(_ context.Context, _ storage.Repository) error { return nil }
func (s *testStore) GetRepository(_ context.Context, _ int64) (*storage.Repository, error) {
	return nil, nil
}
func (s *testStore) GetRepositoryByFullName(_ context.Context, _ int64, _ string) (*storage.Repository, error) {
	return nil, nil
}
func (s *testStore) ListRepositoriesByInstallation(_ context.Context, _ int64) ([]storage.Repository, error) {
	return nil, nil
}
func (s *testStore) UpdateManifestSHA(_ context.Context, _ int64, _ string) error { return nil }
func (s *testStore) SaveScan(_ context.Context, _ storage.ScanResult) error        { return nil }
func (s *testStore) GetScan(_ context.Context, _ string) (*storage.ScanResult, error) {
	return nil, nil
}
func (s *testStore) UpdateScanStatus(_ context.Context, _ string, _ storage.ScanStatus) error {
	return nil
}
func (s *testStore) SaveDecision(_ context.Context, _ storage.VerificationDecision) error {
	return nil
}
func (s *testStore) GetStats(_ context.Context, _ int64) (*storage.RepoStats, error) {
	return nil, nil
}
func (s *testStore) GetStatsByInstallation(_ context.Context, _ int64) (*storage.InstallationStats, error) {
	return nil, nil
}
func (s *testStore) GetRecentScans(_ context.Context, _ int64, _ int) ([]storage.RecentScan, error) {
	return nil, nil
}
func (s *testStore) SaveManifestSnapshot(_ context.Context, _ storage.ManifestSnapshot) error {
	return nil
}
func (s *testStore) GetAuditTrail(_ context.Context, _ int64, _, _ time.Time) ([]storage.AuditEntry, error) {
	return nil, nil
}
func (s *testStore) GetManifestHistory(_ context.Context, _ int64, _ int) ([]storage.ManifestSnapshot, error) {
	return nil, nil
}
func (s *testStore) SaveAuditEvent(_ context.Context, _ storage.AuditEvent) error { return nil }
func (s *testStore) GetAuditEvents(_ context.Context, _ int64, _ string, _, _ int) ([]storage.AuditEvent, error) {
	return nil, nil
}
func (s *testStore) GetLastAuditHash(_ context.Context, _ int64) (string, error) { return "", nil }
func (s *testStore) Close() error                                                  { return nil }
