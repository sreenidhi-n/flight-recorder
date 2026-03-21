package manifest_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

func sampleManifest() *manifest.Manifest {
	t1 := time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 20, 10, 5, 0, 0, time.UTC)
	return &manifest.Manifest{
		Version:     "1",
		GeneratedAt: t1,
		Repo:        "github.com/example/myapp",
		Capabilities: []manifest.ManifestEntry{
			{
				ID:          "dep:go:github.com/stripe/stripe-go/v76",
				Name:        "stripe-go",
				Category:    contracts.CatExternalDep,
				Source:      contracts.LayerDependency,
				ConfirmedBy: "developer@example.com",
				ConfirmedAt: &t2,
				Note:        "Payment processing for checkout flow",
				Status:      "confirmed",
			},
			{
				ID:       "ast:go:net/http:Client.Do",
				Name:     "HTTP client outbound request",
				Category: contracts.CatNetworkAccess,
				Source:   contracts.LayerAST,
				Status:   "confirmed",
				Locations: []contracts.CodeLocation{
					{File: "internal/client/api.go", Line: 42},
				},
			},
			{
				ID:       "dep:go:golang.org/x/net",
				Name:     "x/net",
				Category: contracts.CatExternalDep,
				Source:   contracts.LayerDependency,
				Status:   "auto_detected",
			},
		},
	}
}

// TestRoundTrip verifies that Save → Load produces an identical manifest.
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tass.manifest.yaml")

	original := sampleManifest()

	if err := manifest.Save(original, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Version != original.Version {
		t.Errorf("Version: got %q, want %q", loaded.Version, original.Version)
	}
	if loaded.Repo != original.Repo {
		t.Errorf("Repo: got %q, want %q", loaded.Repo, original.Repo)
	}
	if len(loaded.Capabilities) != len(original.Capabilities) {
		t.Fatalf("Capabilities len: got %d, want %d", len(loaded.Capabilities), len(original.Capabilities))
	}
	for i, orig := range original.Capabilities {
		got := loaded.Capabilities[i]
		if got.ID != orig.ID {
			t.Errorf("[%d] ID: got %q, want %q", i, got.ID, orig.ID)
		}
		if got.Category != orig.Category {
			t.Errorf("[%d] Category: got %q, want %q", i, got.Category, orig.Category)
		}
		if got.Status != orig.Status {
			t.Errorf("[%d] Status: got %q, want %q", i, got.Status, orig.Status)
		}
	}
}

// TestDiff verifies the core mechanic: manifest with 3 caps, CapabilitySet
// with 5 caps → Diff returns 2 novel capabilities.
func TestDiff(t *testing.T) {
	existing := sampleManifest() // has 3 capabilities

	detected := contracts.CapabilitySet{
		RepoRoot: "/repo",
		ScanTime: time.Now(),
		Capabilities: []contracts.Capability{
			// Known (in manifest)
			{ID: "dep:go:github.com/stripe/stripe-go/v76", Name: "stripe-go", Category: contracts.CatExternalDep},
			{ID: "ast:go:net/http:Client.Do", Name: "HTTP client outbound request", Category: contracts.CatNetworkAccess},
			{ID: "dep:go:golang.org/x/net", Name: "x/net", Category: contracts.CatExternalDep},
			// Novel (not in manifest)
			{ID: "dep:go:github.com/redis/go-redis/v9", Name: "go-redis", Category: contracts.CatExternalDep},
			{ID: "ast:go:os:WriteFile", Name: "os.WriteFile", Category: contracts.CatFileSystem},
		},
	}

	novel := manifest.Diff(detected, existing)

	if len(novel) != 2 {
		t.Fatalf("Diff: got %d novel capabilities, want 2", len(novel))
	}

	novelIDs := map[string]bool{}
	for _, c := range novel {
		novelIDs[c.ID] = true
	}
	if !novelIDs["dep:go:github.com/redis/go-redis/v9"] {
		t.Error("Diff: missing go-redis capability")
	}
	if !novelIDs["ast:go:os:WriteFile"] {
		t.Error("Diff: missing os.WriteFile capability")
	}
}

// TestDiffEmptyManifest verifies that all detected capabilities are novel
// when the manifest is empty.
func TestDiffEmptyManifest(t *testing.T) {
	empty := &manifest.Manifest{Version: "1"}

	detected := contracts.CapabilitySet{
		Capabilities: []contracts.Capability{
			{ID: "dep:go:github.com/some/pkg"},
			{ID: "dep:go:github.com/other/pkg"},
		},
	}

	novel := manifest.Diff(detected, empty)
	if len(novel) != 2 {
		t.Errorf("Diff with empty manifest: got %d novel, want 2", len(novel))
	}
}

// TestDiffAllKnown verifies that no capabilities are novel when all are in the manifest.
func TestDiffAllKnown(t *testing.T) {
	existing := sampleManifest() // 3 capabilities

	detected := contracts.CapabilitySet{
		Capabilities: []contracts.Capability{
			{ID: "dep:go:github.com/stripe/stripe-go/v76"},
			{ID: "ast:go:net/http:Client.Do"},
			{ID: "dep:go:golang.org/x/net"},
		},
	}

	novel := manifest.Diff(detected, existing)
	if len(novel) != 0 {
		t.Errorf("Diff all-known: got %d novel, want 0", len(novel))
	}
}

// TestMarshalHasHeader verifies the generated YAML includes the expected header comment.
func TestMarshalHasHeader(t *testing.T) {
	m := sampleManifest()
	data, err := manifest.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	content := string(data)
	if len(content) == 0 {
		t.Fatal("Marshal returned empty output")
	}
	// Header comment should be present
	if content[:2] != "# " {
		t.Errorf("expected output to start with comment, got: %q", content[:20])
	}
}

// TestLoadBytes verifies that LoadBytes works independently of the filesystem.
func TestLoadBytes(t *testing.T) {
	m := sampleManifest()
	data, err := manifest.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	loaded, err := manifest.LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if loaded.Repo != m.Repo {
		t.Errorf("Repo: got %q, want %q", loaded.Repo, m.Repo)
	}
}

// TestFromCapabilitySet verifies auto-generated manifests.
func TestFromCapabilitySet(t *testing.T) {
	cs := contracts.CapabilitySet{
		RepoRoot: "/myapp",
		ScanTime: time.Now(),
		Capabilities: []contracts.Capability{
			{ID: "dep:go:golang.org/x/net", Name: "x/net", Category: contracts.CatExternalDep, Source: contracts.LayerDependency},
			{ID: "dep:go:github.com/stretchr/testify", Name: "testify", Category: contracts.CatExternalDep, Source: contracts.LayerDependency},
		},
	}

	m := manifest.FromCapabilitySet(cs, "github.com/example/myapp")
	if m.Repo != "github.com/example/myapp" {
		t.Errorf("Repo: got %q", m.Repo)
	}
	if len(m.Capabilities) != 2 {
		t.Fatalf("Capabilities: got %d, want 2", len(m.Capabilities))
	}
	for _, e := range m.Capabilities {
		if e.Status != "auto_detected" {
			t.Errorf("entry %q: Status=%q, want auto_detected", e.ID, e.Status)
		}
		if e.FirstDetected == nil {
			t.Errorf("entry %q: FirstDetected is nil", e.ID)
		}
	}
}

// TestSaveAndLoadFile verifies file I/O round-trip produces a parseable file.
func TestSaveAndLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tass.manifest.yaml")

	m := sampleManifest()
	if err := manifest.Save(m, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify the file exists and is non-empty
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() == 0 {
		t.Error("manifest file is empty")
	}

	loaded, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Capabilities) != 3 {
		t.Errorf("Capabilities: got %d, want 3", len(loaded.Capabilities))
	}
}
