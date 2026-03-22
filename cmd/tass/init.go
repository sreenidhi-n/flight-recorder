package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/manifest"
)

const manifestFilename = "tass.manifest.yaml"

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := fs.String("path", ".", "path to repo root")
	rulesDir := fs.String("rules-dir", "./rules", "path to rules directory (for AST scanning)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("tass init: %w", err)
	}

	repoRoot, err := filepath.Abs(*path)
	if err != nil {
		return fmt.Errorf("tass init: resolve path: %w", err)
	}

	manifestPath := filepath.Join(repoRoot, manifestFilename)
	if _, err := os.Stat(manifestPath); err == nil {
		slog.Warn("tass.manifest.yaml already exists — overwriting", "path", manifestPath)
	}

	slog.Info("scanning repository for capabilities", "root", repoRoot)

	// Build the AST scanner from the rules directory (optional — init works without it).
	absRulesDir, _ := filepath.Abs(*rulesDir)
	astScanner, err := scanner.NewASTScannerFromDir(absRulesDir)
	if err != nil {
		slog.Warn("tass init: could not load AST rules, running Layer 0 only",
			"rules-dir", absRulesDir, "err", err)
		astScanner = nil
	}

	s := scanner.New(scanner.DefaultRegistry, astScanner)
	cs, err := s.ScanRepo(repoRoot)
	if err != nil {
		return fmt.Errorf("tass init: scan: %w", err)
	}

	// Derive a repo identifier from the directory name.
	// In Phase 3 this comes from the GitHub API; for now, use the folder name.
	repoName := filepath.Base(repoRoot)

	m := manifest.FromCapabilitySet(*cs, repoName)

	if err := manifest.Save(m, manifestPath); err != nil {
		return fmt.Errorf("tass init: save manifest: %w", err)
	}

	l0count, l1count := 0, 0
	for _, c := range cs.Capabilities {
		if c.Source == "layer0_dependency" {
			l0count++
		} else {
			l1count++
		}
	}

	fmt.Printf("\nFound %d capabilities (%d dependencies, %d AST detections).\n",
		len(cs.Capabilities), l0count, l1count)
	fmt.Printf("Manifest written to: %s\n\n", manifestPath)
	fmt.Println("Next steps:")
	fmt.Println("  1. Review tass.manifest.yaml — add notes for any entries that need context.")
	fmt.Println("  2. Commit the manifest alongside your source code.")
	fmt.Println("  3. Install the TASS GitHub App to start scanning PRs automatically.")

	return nil
}

