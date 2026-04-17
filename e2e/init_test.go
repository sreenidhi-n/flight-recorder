// Package e2e contains end-to-end tests that exercise the TASS binary directly.
// These tests create real temp directories and run the compiled binary.
package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tass-security/tass/pkg/manifest"
)

// binaryPath returns the path to the compiled tass binary.
// Tests build it once via TestMain or rely on it being pre-built.
func binaryPath(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	bin := filepath.Join(root, "tass")
	// Always rebuild so the binary matches the current source.
	ldflags := `-X main.version=v3.0.0-dev -X main.commit=none -X main.buildDate=unknown`
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, "./cmd/tass")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build tass binary: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// e2e/ is one level below repo root.
	here, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	return filepath.Dir(here)
}

// TestVersionFlag is the Step 1.1 smoke test re-run in e2e context.
func TestVersionFlag(t *testing.T) {
	bin := binaryPath(t)
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		t.Fatalf("tass --version: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if !strings.HasPrefix(got, "tass v3.0.0-dev") {
		t.Errorf("--version: got %q, want prefix %q", got, "tass v3.0.0-dev")
	}
}

// TestInitSyntheticGoMod creates a temp directory with a synthetic go.mod,
// runs `tass init`, and validates the generated manifest.
func TestInitSyntheticGoMod(t *testing.T) {
	bin := binaryPath(t)
	dir := t.TempDir()

	// Write a synthetic go.mod with 3 direct deps and 1 indirect.
	gomod := []byte(`module github.com/example/testapp

go 1.22

require (
	github.com/stripe/stripe-go/v76 v76.3.0
	github.com/redis/go-redis/v9 v9.4.0
	gopkg.in/yaml.v3 v3.0.1
	golang.org/x/sys v0.20.0 // indirect
)
`)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// Run tass init
	cmd := exec.Command(bin, "init", "--path", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tass init failed: %v\n%s", err, out)
	}

	output := string(out)
	t.Logf("tass init output:\n%s", output)

	// Verify manifest was created
	manifestPath := filepath.Join(dir, "tass.manifest.yaml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("tass.manifest.yaml was not created")
	}

	// Load and validate the manifest
	m, err := manifest.Load(manifestPath)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}

	// Should have exactly 3 direct deps (indirect skipped)
	if len(m.Capabilities) != 3 {
		t.Errorf("capabilities: got %d, want 3 (indirect should be skipped)", len(m.Capabilities))
		for _, c := range m.Capabilities {
			t.Logf("  - %s", c.ID)
		}
	}

	// Verify expected IDs
	ids := map[string]bool{}
	for _, c := range m.Capabilities {
		ids[c.ID] = true
	}
	expected := []string{
		"dep:go:github.com/stripe/stripe-go/v76",
		"dep:go:github.com/redis/go-redis/v9",
		"dep:go:gopkg.in/yaml.v3",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected capability %q not found in manifest", id)
		}
	}
	// Indirect should NOT be present
	if ids["dep:go:golang.org/x/sys"] {
		t.Error("indirect dep golang.org/x/sys should not appear in manifest")
	}

	// All entries should be auto_detected
	for _, c := range m.Capabilities {
		if c.Status != "auto_detected" {
			t.Errorf("%s: Status=%q, want auto_detected", c.ID, c.Status)
		}
	}

	// Verify output message mentions capability count
	if !strings.Contains(output, "Found 3 capabilities") {
		t.Errorf("output should say 'Found 3 capabilities', got:\n%s", output)
	}
}

// TestInitNoGoMod verifies tass init on a directory with no known dep files
// produces an empty manifest without crashing.
func TestInitNoGoMod(t *testing.T) {
	bin := binaryPath(t)
	dir := t.TempDir()

	cmd := exec.Command(bin, "init", "--path", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tass init (no dep files) failed: %v\n%s", err, out)
	}

	m, err := manifest.Load(filepath.Join(dir, "tass.manifest.yaml"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(m.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities for empty dir, got %d", len(m.Capabilities))
	}
}

// TestInitMultipleGoMod verifies nested go.mod files are all discovered.
func TestInitMultipleGoMod(t *testing.T) {
	bin := binaryPath(t)
	dir := t.TempDir()

	// Root go.mod
	root := []byte(`module github.com/example/root

go 1.22

require github.com/stripe/stripe-go/v76 v76.3.0
`)
	// Subdir go.mod (simulates a Go workspace or embedded module)
	sub := []byte(`module github.com/example/sub

go 1.22

require github.com/redis/go-redis/v9 v9.4.0
`)
	subdir := filepath.Join(dir, "internal", "worker")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), root, 0644); err != nil {
		t.Fatalf("write root go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "go.mod"), sub, 0644); err != nil {
		t.Fatalf("write sub go.mod: %v", err)
	}

	cmd := exec.Command(bin, "init", "--path", dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tass init: %v\n%s", err, out)
	}
	t.Logf("output:\n%s", out)

	m, err := manifest.Load(filepath.Join(dir, "tass.manifest.yaml"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}

	// Both modules' direct deps should appear (deduplicated by ID)
	if len(m.Capabilities) < 2 {
		t.Errorf("expected >=2 capabilities from 2 go.mod files, got %d", len(m.Capabilities))
	}
}

// TestInitManifestRoundTrip verifies the generated manifest can be loaded
// and diffed without error — an indirect test of the full Phase 1 pipeline.
func TestInitManifestRoundTrip(t *testing.T) {
	bin := binaryPath(t)
	dir := t.TempDir()

	gomod := []byte(`module github.com/example/app

go 1.22

require github.com/some/library v1.0.0
`)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	cmd := exec.Command(bin, "init", "--path", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tass init: %v\n%s", err, out)
	}

	// Load the manifest
	m, err := manifest.Load(filepath.Join(dir, "tass.manifest.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The manifest should have exactly 1 capability.
	if len(m.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(m.Capabilities))
	}

	// Verify it's parseable and the version field is set.
	if m.Version == "" {
		t.Error("manifest Version is empty")
	}
	if m.Repo == "" {
		t.Error("manifest Repo is empty")
	}
}
