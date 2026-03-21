package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

const manifestFilename = "tass.manifest.yaml"

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := fs.String("path", ".", "path to repo root")
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

	cs, filesScanned, err := scanRepo(repoRoot)
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

	fmt.Printf("\nFound %d capabilities across %d dependency file(s).\n", len(cs.Capabilities), filesScanned)
	fmt.Printf("Manifest written to: %s\n\n", manifestPath)
	fmt.Println("Next steps:")
	fmt.Println("  1. Review tass.manifest.yaml — add notes for any entries that need context.")
	fmt.Println("  2. Commit the manifest alongside your source code.")
	fmt.Println("  3. Install the TASS GitHub App to start scanning PRs automatically.")

	return nil
}

// scanRepo walks repoRoot looking for known dependency files and parses each one.
// Returns the aggregated CapabilitySet and the number of files scanned.
func scanRepo(repoRoot string) (*contracts.CapabilitySet, int, error) {
	registry := scanner.DefaultRegistry
	allCaps := make([]contracts.Capability, 0)
	filesScanned := 0

	// Deduplicate capabilities by ID — Layer 0 is authoritative for dep entries.
	seen := make(map[string]struct{})

	for filename, parser := range registry {
		// Walk the entire tree for each known dep file pattern.
		err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Skip hidden directories (e.g. .git, .github).
			if info.IsDir() && len(info.Name()) > 0 && info.Name()[0] == '.' {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			if info.Name() != filename {
				return nil
			}

			slog.Info("parsing dependency file", "file", path, "parser", parser.FilePattern())
			caps, err := scanner.ParseFile(parser, path)
			if err != nil {
				// Log and continue — don't abort on a single bad file.
				slog.Warn("failed to parse dependency file", "file", path, "err", err)
				return nil
			}

			filesScanned++
			for _, cap := range caps {
				if _, ok := seen[cap.ID]; !ok {
					seen[cap.ID] = struct{}{}
					// Record which specific file we found it in.
					cap.Location.File = relPath(repoRoot, path)
					allCaps = append(allCaps, cap)
				}
			}
			return nil
		})
		if err != nil {
			return nil, filesScanned, fmt.Errorf("walk for %s: %w", filename, err)
		}
	}

	cs := &contracts.CapabilitySet{
		RepoRoot:     repoRoot,
		ScanTime:     time.Now().UTC(),
		Capabilities: allCaps,
	}
	return cs, filesScanned, nil
}

// relPath returns path relative to base, or path unchanged if that fails.
func relPath(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}
