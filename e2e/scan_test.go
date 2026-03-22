package e2e_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
)

// rulesDir returns the absolute path to the rules/ directory for e2e tests.
func rulesDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "rules")
}

// initScanRepo creates a temp git repo, writes a go.mod, runs tass init,
// and commits — leaving the repo ready for tass scan tests.
func initScanRepo(t *testing.T, bin, goModContent string) string {
	t.Helper()
	dir := t.TempDir()

	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "TASS Test"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// Run tass init to create the baseline manifest.
	cmd := exec.Command(bin, "init", "--path", dir, "--rules-dir", rulesDir(t))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tass init: %v\n%s", err, out)
	}

	for _, args := range [][]string{
		{"add", "."},
		{"commit", "-m", "initial baseline"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	return dir
}

// TestScanCleanRepo verifies that tass scan exits 0 when there are no novel
// capabilities (diff against the commit that created the manifest).
func TestScanCleanRepo(t *testing.T) {
	bin := binaryPath(t)
	dir := initScanRepo(t, bin, `module github.com/example/test

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.11
	github.com/golang-jwt/jwt/v5 v5.2.0
)
`)

	cmd := exec.Command(bin, "scan",
		"--path", dir,
		"--base", "HEAD",
		"--rules-dir", rulesDir(t),
		"--format", "text",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tass scan (clean): exit non-zero: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "No novel capabilities") {
		t.Errorf("expected 'No novel capabilities', got:\n%s", out)
	}
}

// TestScanNewDep verifies that tass scan exits 1 and reports the new dependency
// when a new require is added after the baseline manifest was created.
func TestScanNewDep(t *testing.T) {
	bin := binaryPath(t)
	dir := initScanRepo(t, bin, `module github.com/example/test

go 1.22

require github.com/go-chi/chi/v5 v5.0.11
`)

	// Add a new dependency and commit it.
	newGoMod := `module github.com/example/test

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.11
	github.com/stripe/stripe-go/v76 v76.3.0
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(newGoMod), 0644); err != nil {
		t.Fatalf("write new go.mod: %v", err)
	}
	for _, args := range [][]string{
		{"add", "go.mod"},
		{"commit", "-m", "add stripe"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// tass scan should exit 1 (novel capabilities found).
	cmd := exec.Command(bin, "scan",
		"--path", dir,
		"--base", "HEAD~1",
		"--rules-dir", rulesDir(t),
		"--format", "text",
	)
	out, _ := cmd.CombinedOutput()

	if cmd.ProcessState.ExitCode() != 1 {
		t.Errorf("expected exit code 1 (novel caps), got %d\noutput:\n%s",
			cmd.ProcessState.ExitCode(), out)
	}
	if !strings.Contains(string(out), "dep:go:github.com/stripe/stripe-go/v76") {
		t.Errorf("expected stripe capability in output, got:\n%s", out)
	}
}

// TestScanRemovedDep verifies that removing a dependency does not produce a novel
// capability — removed deps are informational only.
func TestScanRemovedDep(t *testing.T) {
	bin := binaryPath(t)
	dir := initScanRepo(t, bin, `module github.com/example/test

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.11
	github.com/stripe/stripe-go/v76 v76.3.0
)
`)

	// Remove stripe.
	reduced := `module github.com/example/test

go 1.22

require github.com/go-chi/chi/v5 v5.0.11
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(reduced), 0644); err != nil {
		t.Fatalf("write reduced go.mod: %v", err)
	}
	for _, args := range [][]string{
		{"add", "go.mod"},
		{"commit", "-m", "remove stripe"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	cmd := exec.Command(bin, "scan",
		"--path", dir,
		"--base", "HEAD~1",
		"--rules-dir", rulesDir(t),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tass scan (removed dep): exit non-zero: %v\noutput:\n%s", err, out)
	}
}

// TestScanJSONFormat verifies that --format json produces valid JSON output.
func TestScanJSONFormat(t *testing.T) {
	bin := binaryPath(t)
	dir := initScanRepo(t, bin, `module github.com/example/test

go 1.22

require github.com/go-chi/chi/v5 v5.0.11
`)

	// Add a new dep so there's something to report.
	newGoMod := `module github.com/example/test

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.11
	github.com/sendgrid/sendgrid-go v3.14.0+incompatible
)
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(newGoMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	for _, args := range [][]string{
		{"add", "go.mod"},
		{"commit", "-m", "add sendgrid"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	cmd := exec.Command(bin, "scan",
		"--path", dir,
		"--base", "HEAD~1",
		"--rules-dir", rulesDir(t),
		"--format", "json",
	)
	out, _ := cmd.CombinedOutput()

	var caps []contracts.Capability
	if err := json.Unmarshal(out, &caps); err != nil {
		t.Fatalf("--format json: invalid JSON: %v\noutput:\n%s", err, out)
	}
	if len(caps) != 1 || caps[0].ID != "dep:go:github.com/sendgrid/sendgrid-go" {
		t.Errorf("expected 1 capability (sendgrid), got %d: %v", len(caps), caps)
	}
}

// TestScanNoManifest verifies tass scan exits with an error when no manifest exists.
func TestScanNoManifest(t *testing.T) {
	bin := binaryPath(t)
	dir := t.TempDir()

	cmd := exec.Command(bin, "scan", "--path", dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit when no manifest exists")
	}
	if !strings.Contains(string(out), "tass init") {
		t.Errorf("expected hint to run 'tass init', got:\n%s", out)
	}
}

// TestScanOwnRepo runs tass scan on the TASS repo itself against HEAD (no changes)
// and verifies it completes cleanly in under 30 seconds.
func TestScanOwnRepo(t *testing.T) {
	bin := binaryPath(t)
	root := repoRoot(t)

	// Ensure a manifest exists (it should, since it's committed to the repo).
	if _, err := os.Stat(filepath.Join(root, "tass.manifest.yaml")); os.IsNotExist(err) {
		t.Skip("tass.manifest.yaml not found in repo root — run 'tass init' first")
	}

	start := time.Now()
	cmd := exec.Command(bin, "scan",
		"--path", root,
		"--base", "HEAD",
		"--rules-dir", rulesDir(t),
	)
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("tass scan own repo: exit non-zero: %v\noutput:\n%s", err, out)
	}
	if elapsed > 30*time.Second {
		t.Errorf("tass scan took %v, want <30s", elapsed)
	}
	t.Logf("tass scan own repo: %v\n%s", elapsed, out)
}
