package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

// runScan implements `tass scan`. Returns (exitCode, error):
//   - (0, nil)  → no novel capabilities detected
//   - (1, nil)  → novel capabilities found (expected — this is the signal)
//   - (1, err)  → operational failure
func runScan(args []string) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	base := fs.String("base", "main", "base branch to diff against")
	format := fs.String("format", "text", "output format: text or json")
	rulesDir := fs.String("rules-dir", "./rules", "path to rules directory")
	path := fs.String("path", ".", "path to repo root")
	ci := fs.Bool("ci", false, "emit GitHub Actions annotations (::warning::) alongside output")
	exportTo := fs.String("export-to", "", "send results to a TASS server URL (e.g. https://tass-test.fly.dev/api/import)")
	exportToken := fs.String("token", "", "API token for --export-to (or set TASS_IMPORT_TOKEN env var)")
	repo := fs.String("repo", "", "repo name for --export-to, e.g. owner/my-service (auto-detected from git remote if omitted)")
	branch := fs.String("branch", "", "branch name for --export-to (auto-detected from git if omitted)")
	if err := fs.Parse(args); err != nil {
		return 1, fmt.Errorf("tass scan: %w", err)
	}

	if *format != "text" && *format != "json" {
		return 1, fmt.Errorf("tass scan: --format must be \"text\" or \"json\", got %q", *format)
	}

	repoRoot, err := filepath.Abs(*path)
	if err != nil {
		return 1, fmt.Errorf("tass scan: resolve path: %w", err)
	}

	// Load existing manifest — must exist. Surface a clear action if missing.
	manifestPath := filepath.Join(repoRoot, manifestFilename)
	existing, err := manifest.Load(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			color.Red("✗  tass.manifest.yaml not found in %s", repoRoot)
			fmt.Fprintln(os.Stderr, "   Run 'tass init' first to generate the baseline manifest.")
			return 1, nil // user error, not a Go error
		}
		// YAML parse error — yaml.v3 includes line:col in the message.
		if isYAMLError(err) {
			color.Red("✗  tass.manifest.yaml is invalid:")
			fmt.Fprintf(os.Stderr, "   %v\n", err)
			fmt.Fprintln(os.Stderr, "   Fix the YAML or run 'tass init' to regenerate the manifest.")
			return 1, nil
		}
		return 1, fmt.Errorf("tass scan: load manifest: %w", err)
	}

	// Build AST scanner — uses embedded rules unless --rules-dir is explicitly
	// set to a real directory (e.g. during rule authoring).
	astScanner, err := buildASTScanner(*rulesDir)
	if err != nil {
		color.Yellow("  warning: could not load AST rules (%v) — running Layer 0 only", err)
		astScanner = nil
	}

	s := scanner.New(scanner.DefaultRegistry, astScanner)
	cs, err := s.ScanDiff(repoRoot, *base)
	if err != nil {
		if isNoGitError(err) {
			color.Red("✗  Not a git repository (or git is not installed).")
			fmt.Fprintf(os.Stderr, "   tass scan requires git. Ensure %s is inside a git repo.\n", repoRoot)
			return 1, nil
		}
		return 1, fmt.Errorf("tass scan: diff scan: %w", err)
	}

	novel := manifest.Diff(*cs, existing)

	if len(novel) == 0 {
		switch *format {
		case "json":
			fmt.Println("[]")
		default:
			color.Green("✓  No novel capabilities detected.")
			if *ci {
				fmt.Println("::notice::TASS: no novel capabilities detected — all clear.")
			}
		}
		return 0, nil
	}

	// Output novel capabilities.
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(novel); err != nil {
			return 1, fmt.Errorf("tass scan: encode json: %w", err)
		}
		if *ci {
			// Emit GitHub Actions annotations on stderr.
			for _, c := range novel {
				file := c.Location.File
				line := c.Location.Line
				if line > 0 {
					fmt.Fprintf(os.Stderr, "::warning file=%s,line=%d::TASS: novel capability %q (%s)\n",
						file, line, c.Name, c.Category)
				} else {
					fmt.Fprintf(os.Stderr, "::warning file=%s::TASS: novel capability %q (%s)\n",
						file, c.Name, c.Category)
				}
			}
		}

	default: // "text"
		header := color.New(color.FgYellow, color.Bold).SprintfFunc()
		capID := color.New(color.FgCyan).SprintfFunc()
		loc := color.New(color.Faint).SprintfFunc()

		fmt.Printf("\n%s\n\n", header("TASS scan — %d novel %s detected",
			len(novel), plural(len(novel), "capability", "capabilities")))

		for i, c := range novel {
			fmt.Printf("  + %s  [%s]\n", capID("%-50s", c.ID), c.Category)
			fmt.Printf("    Name:       %s\n", c.Name)
			file := c.Location.File
			if c.Location.Line > 0 {
				file = fmt.Sprintf("%s:%d", file, c.Location.Line)
			}
			fmt.Printf("    File:       %s\n", loc(file))
			fmt.Printf("    Confidence: %.0f%%\n", c.Confidence*100)
			fmt.Println()

			if *ci {
				// Emit GitHub Actions annotation for each novel cap.
				if c.Location.Line > 0 {
					fmt.Fprintf(os.Stderr,
						"::warning file=%s,line=%d,title=TASS #%d::Novel capability %q (%s) — not in manifest\n",
						c.Location.File, c.Location.Line, i+1, c.Name, c.Category)
				} else {
					fmt.Fprintf(os.Stderr,
						"::warning title=TASS #%d::Novel capability %q (%s) — not in manifest\n",
						i+1, c.Name, c.Category)
				}
			}
		}

		fmt.Println("Open a PR and let the TASS GitHub App handle verification,")
		fmt.Println("or run 'tass init' to accept these as the new baseline.")
		fmt.Println()
	}

	// --- Optional: export results to hosted dashboard ---
	if *exportTo != "" {
		verifyURL, exportErr := exportResults(novel, *exportTo, *exportToken, *repo, *branch, repoRoot)
		if exportErr != nil {
			color.Yellow("  warning: export failed: %v", exportErr)
		} else {
			color.Cyan("\n  → Review & verify on TASS: %s\n", verifyURL)
		}
	}

	return 1, nil
}

// exportResults POSTs novel capabilities to a hosted TASS server and returns
// the verify URL from the response.
func exportResults(novel []contracts.Capability, serverURL, token, repoName, branchName, repoRoot string) (string, error) {
	// Auto-detect token from env if not provided via flag.
	if token == "" {
		token = os.Getenv("TASS_IMPORT_TOKEN")
	}
	if token == "" {
		return "", fmt.Errorf("--token or TASS_IMPORT_TOKEN is required for --export-to")
	}

	// Auto-detect repo and branch from git if not provided.
	if repoName == "" {
		repoName = gitRemoteRepo(repoRoot)
	}
	if branchName == "" {
		branchName = gitCurrentBranch(repoRoot)
	}

	type exportReq struct {
		Repo         string                 `json:"repo"`
		Branch       string                 `json:"branch"`
		Capabilities []contracts.Capability `json:"capabilities"`
	}
	body, err := json.Marshal(exportReq{
		Repo:         repoName,
		Branch:       branchName,
		Capabilities: novel,
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, serverURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		VerifyURL string `json:"verify_url"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return result.VerifyURL, nil
}

// gitCurrentBranch returns the current branch name from git, or "local" on failure.
func gitCurrentBranch(repoRoot string) string {
	out, err := runGit(repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "local"
	}
	return strings.TrimSpace(out)
}

// gitRemoteRepo tries to extract "owner/repo" from the origin remote URL.
// Returns empty string on failure — the server will use a fallback.
func gitRemoteRepo(repoRoot string) string {
	out, err := runGit(repoRoot, "remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	u := strings.TrimSpace(out)
	// Handle SSH: git@github.com:owner/repo.git
	if strings.HasPrefix(u, "git@") {
		u = strings.TrimPrefix(u, "git@github.com:")
	}
	// Handle HTTPS: https://github.com/owner/repo.git
	for _, prefix := range []string{"https://github.com/", "http://github.com/"} {
		u = strings.TrimPrefix(u, prefix)
	}
	u = strings.TrimSuffix(u, ".git")
	// Validate: must be "owner/repo"
	if strings.Count(u, "/") == 1 && !strings.Contains(u, ":") {
		return u
	}
	return ""
}

// runGit runs a git command in repoRoot and returns its stdout.
func runGit(repoRoot string, gitArgs ...string) (string, error) {
	args := append([]string{"-C", repoRoot}, gitArgs...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// isNoGitError heuristically detects "not a git repo" errors.
func isNoGitError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not a git repository") ||
		strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "git: command not found")
}

// isYAMLError heuristically detects YAML parse errors from gopkg.in/yaml.v3.
func isYAMLError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "yaml:") ||
		strings.Contains(msg, "YAML") ||
		strings.Contains(msg, "unmarshal")
}
