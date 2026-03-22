package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/manifest"
)

// runScan implements `tass scan`. It returns (exitCode, error):
//   - (0, nil)  → no novel capabilities detected
//   - (1, nil)  → novel capabilities found (not an error — it's a status)
//   - (1, err)  → operational failure (bad flags, missing manifest, etc.)
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

	// Load existing manifest — must exist (run `tass init` first).
	manifestPath := filepath.Join(repoRoot, manifestFilename)
	existing, err := manifest.Load(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 1, fmt.Errorf("tass.manifest.yaml not found in %s — run 'tass init' first", repoRoot)
		}
		return 1, fmt.Errorf("tass scan: load manifest: %w", err)
	}

	// Build AST scanner from rules directory.
	absRulesDir, _ := filepath.Abs(*rulesDir)
	astScanner, err := scanner.NewASTScannerFromDir(absRulesDir)
	if err != nil {
		// Non-fatal: fall back to Layer 0 only and warn.
		fmt.Fprintf(os.Stderr, "warning: could not load AST rules (%v) — running Layer 0 only\n", err)
		astScanner = nil
	}

	s := scanner.New(scanner.DefaultRegistry, astScanner)
	cs, err := s.ScanDiff(repoRoot, *base)
	if err != nil {
		return 1, fmt.Errorf("tass scan: diff scan: %w", err)
	}

	// Diff detected capabilities against the manifest to find novel ones.
	novel := manifest.Diff(*cs, existing)

	if len(novel) == 0 {
		if *format == "text" {
			fmt.Println("No novel capabilities detected.")
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
		fmt.Fprintf(os.Stdout, "TASS scan — %d novel capability(s) detected\n\n", len(novel))
		for _, c := range novel {
			fmt.Fprintf(os.Stdout, "  + %-50s [%s]\n", c.ID, c.Category)
			fmt.Fprintf(os.Stdout, "    Name:       %s\n", c.Name)
			fmt.Fprintf(os.Stdout, "    File:       %s", c.Location.File)
			if c.Location.Line > 0 {
				fmt.Fprintf(os.Stdout, ":%d", c.Location.Line)
			}
			fmt.Fprintln(os.Stdout)
			fmt.Fprintf(os.Stdout, "    Confidence: %.0f%%\n", c.Confidence*100)
			fmt.Fprintln(os.Stdout)
		}
		fmt.Println("Run 'tass init' to accept these as baseline, or open a PR and let the")
		fmt.Println("TASS GitHub App handle verification.")
	}

	return 1, nil
}
