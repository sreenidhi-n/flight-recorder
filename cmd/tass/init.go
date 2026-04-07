package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
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
		color.Yellow("⚠  tass.manifest.yaml already exists — overwriting")
	}

	fmt.Printf("Scanning %s for capabilities…\n", repoRoot)

	// Build the AST scanner from the rules directory (optional).
	absRulesDir, _ := filepath.Abs(*rulesDir)
	astScanner, err := scanner.NewASTScannerFromDir(absRulesDir)
	if err != nil {
		color.Yellow("  warning: could not load AST rules (%v) — running Layer 0 only", err)
		astScanner = nil
	}

	s := scanner.New(scanner.DefaultRegistry, astScanner)
	cs, err := s.ScanRepo(repoRoot)
	if err != nil {
		return fmt.Errorf("tass init: scan: %w", err)
	}

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

	green := color.New(color.FgGreen, color.Bold).SprintfFunc()
	dim := color.New(color.Faint).SprintfFunc()

	fmt.Printf("\n%s  Found %d %s  %s\n",
		green("✓"),
		len(cs.Capabilities),
		plural(len(cs.Capabilities), "capability", "capabilities"),
		dim("(%d deps, %d AST detections)", l0count, l1count),
	)
	fmt.Printf("  Manifest written to: %s\n\n", color.CyanString(manifestPath))

	fmt.Println(color.New(color.Bold).Sprint("Next steps:"))
	fmt.Println("  1. Review tass.manifest.yaml — add notes for entries that need context.")
	fmt.Println("  2. Commit the manifest alongside your source code.")
	fmt.Println("  3. Install the TASS GitHub App to start scanning PRs automatically.")
	fmt.Println()

	return nil
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}
