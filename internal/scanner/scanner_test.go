package scanner_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

// TestScanRepo_OwnRepo scans the TASS repository itself and validates the result.
// This is the dogfooding test: if TASS can't scan itself, something is wrong.
func TestScanRepo_OwnRepo(t *testing.T) {
	repoRoot := filepath.Join(repoRulesDir(t), "..") // rules/../ = repo root

	astScanner, err := scanner.NewASTScannerFromDir(repoRulesDir(t))
	if err != nil {
		t.Fatalf("NewASTScannerFromDir: %v", err)
	}

	s := scanner.New(scanner.DefaultRegistry, astScanner)
	cs, err := s.ScanRepo(repoRoot)
	if err != nil {
		t.Fatalf("ScanRepo: %v", err)
	}

	if cs == nil {
		t.Fatal("ScanRepo returned nil CapabilitySet")
	}
	if cs.RepoRoot == "" {
		t.Error("CapabilitySet.RepoRoot is empty")
	}
	if cs.ScanTime.IsZero() {
		t.Error("CapabilitySet.ScanTime is zero")
	}

	// TASS itself has at least the go.mod deps (golang.org/x/mod, gopkg.in/yaml.v3,
	// go-tree-sitter) and AST detections (os.ReadFile, exec.Command calls, etc.)
	if len(cs.Capabilities) == 0 {
		t.Error("expected at least one capability from TASS own repo, got 0")
	}

	// Verify all capabilities have valid IDs and categories.
	l0count, l1count := 0, 0
	for _, c := range cs.Capabilities {
		if c.ID == "" {
			t.Errorf("capability with empty ID: %+v", c)
		}
		if c.Category == "" {
			t.Errorf("%s: empty category", c.ID)
		}
		switch c.Source {
		case contracts.LayerDependency:
			l0count++
		case contracts.LayerAST:
			l1count++
		default:
			t.Errorf("%s: unknown source layer %q", c.ID, c.Source)
		}
	}

	t.Logf("ScanRepo own repo: %d total (%d L0 dep, %d L1 AST)",
		len(cs.Capabilities), l0count, l1count)
	for _, c := range cs.Capabilities {
		t.Logf("  [%s] %s (%s)", c.Source, c.ID, c.Location.File)
	}
}

// TestScanRepo_Layer0Only verifies the scanner works when astScanner is nil.
func TestScanRepo_Layer0Only(t *testing.T) {
	repoRoot := filepath.Join(repoRulesDir(t), "..")

	s := scanner.New(scanner.DefaultRegistry, nil)
	cs, err := s.ScanRepo(repoRoot)
	if err != nil {
		t.Fatalf("ScanRepo Layer0Only: %v", err)
	}

	for _, c := range cs.Capabilities {
		if c.Source != contracts.LayerDependency {
			t.Errorf("Layer0-only scan returned non-L0 capability: %s (%s)", c.ID, c.Source)
		}
	}
	t.Logf("Layer0-only: %d capabilities", len(cs.Capabilities))
}

// TestScanDiff_NoChangedFiles verifies that a diff with no changed files
// returns an empty CapabilitySet without error.
func TestScanDiff_NoChangedFiles(t *testing.T) {
	repoRoot := filepath.Join(repoRulesDir(t), "..")

	s := scanner.New(scanner.DefaultRegistry, nil)
	// HEAD...HEAD has no changes by definition.
	cs, err := s.ScanDiff(repoRoot, "HEAD")
	if err != nil {
		t.Fatalf("ScanDiff HEAD...HEAD: %v", err)
	}
	if len(cs.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities for HEAD...HEAD diff, got %d", len(cs.Capabilities))
	}
}

// TestScanDiff_NewGoMod creates a synthetic git repo, adds a go.mod with a new
// dependency on a branch, and verifies ScanDiff detects it.
func TestScanDiff_NewGoMod(t *testing.T) {
	dir := t.TempDir()
	initGitRepoForScanner(t, dir)

	// Baseline commit: go.mod with one dep.
	writeFile(t, filepath.Join(dir, "go.mod"), `module github.com/example/test

go 1.22

require github.com/go-chi/chi/v5 v5.0.11
`)
	gitRun(t, dir, "add", "go.mod")
	gitRun(t, dir, "commit", "-m", "initial")

	// New commit on same branch: add a second dependency.
	writeFile(t, filepath.Join(dir, "go.mod"), `module github.com/example/test

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.11
	github.com/stripe/stripe-go/v76 v76.3.0
)
`)
	gitRun(t, dir, "add", "go.mod")
	gitRun(t, dir, "commit", "-m", "add stripe")

	s := scanner.New(scanner.DefaultRegistry, nil)
	cs, err := s.ScanDiff(dir, "HEAD~1")
	if err != nil {
		t.Fatalf("ScanDiff: %v", err)
	}

	if len(cs.Capabilities) != 1 {
		t.Fatalf("expected 1 novel capability (stripe), got %d: %v",
			len(cs.Capabilities), capIDs(cs.Capabilities))
	}
	if cs.Capabilities[0].ID != "dep:go:github.com/stripe/stripe-go/v76" {
		t.Errorf("unexpected capability ID: %q", cs.Capabilities[0].ID)
	}
}

// TestScanDiff_RemovedDepNotReported verifies removed deps are not flagged as novel.
func TestScanDiff_RemovedDepNotReported(t *testing.T) {
	dir := t.TempDir()
	initGitRepoForScanner(t, dir)

	writeFile(t, filepath.Join(dir, "go.mod"), `module github.com/example/test

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.11
	github.com/stripe/stripe-go/v76 v76.3.0
)
`)
	gitRun(t, dir, "add", "go.mod")
	gitRun(t, dir, "commit", "-m", "initial")

	// Remove stripe.
	writeFile(t, filepath.Join(dir, "go.mod"), `module github.com/example/test

go 1.22

require github.com/go-chi/chi/v5 v5.0.11
`)
	gitRun(t, dir, "add", "go.mod")
	gitRun(t, dir, "commit", "-m", "remove stripe")

	s := scanner.New(scanner.DefaultRegistry, nil)
	cs, err := s.ScanDiff(dir, "HEAD~1")
	if err != nil {
		t.Fatalf("ScanDiff: %v", err)
	}

	if len(cs.Capabilities) != 0 {
		t.Errorf("removed dep should not appear as novel, got: %v", capIDs(cs.Capabilities))
	}
}

// --- helpers ---

func initGitRepoForScanner(t *testing.T, dir string) {
	t.Helper()
	gitRun(t, dir, "init")
	gitRun(t, dir, "config", "user.email", "test@example.com")
	gitRun(t, dir, "config", "user.name", "Test")
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
