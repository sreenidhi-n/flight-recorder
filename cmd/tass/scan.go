package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/tass-security/tass/internal/scanner"
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

	// Build AST scanner from rules directory.
	absRulesDir, _ := filepath.Abs(*rulesDir)
	astScanner, err := scanner.NewASTScannerFromDir(absRulesDir)
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
		if *format == "text" {
			color.Green("✓  No novel capabilities detected.")
		} else {
			fmt.Println("[]")
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

	default: // "text"
		header := color.New(color.FgYellow, color.Bold).SprintfFunc()
		capID := color.New(color.FgCyan).SprintfFunc()
		loc := color.New(color.Faint).SprintfFunc()

		fmt.Printf("\n%s\n\n", header("TASS scan — %d novel %s detected",
			len(novel), plural(len(novel), "capability", "capabilities")))

		for _, c := range novel {
			fmt.Printf("  + %s  [%s]\n", capID("%-50s", c.ID), c.Category)
			fmt.Printf("    Name:       %s\n", c.Name)
			file := c.Location.File
			if c.Location.Line > 0 {
				file = fmt.Sprintf("%s:%d", file, c.Location.Line)
			}
			fmt.Printf("    File:       %s\n", loc(file))
			fmt.Printf("    Confidence: %.0f%%\n", c.Confidence*100)
			fmt.Println()
		}

		fmt.Println("Open a PR and let the TASS GitHub App handle verification,")
		fmt.Println("or run 'tass init' to accept these as the new baseline.")
		fmt.Println()
	}

	return 1, nil
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
