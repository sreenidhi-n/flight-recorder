package main

import (
	"fmt"
	"log/slog"
	"os"

	tass "github.com/tass-security/tass"
	"github.com/tass-security/tass/internal/scanner"
)

// buildASTScanner returns an ASTScanner using:
//  1. Embedded rules (bundled in the binary) — when rulesDir is "" or the
//     default "./rules" and that directory does not exist locally.
//  2. rulesDir from disk — when the caller explicitly passes a non-empty
//     rulesDir that exists on disk (e.g. for local development of new rules).
//
// The embedded path always wins unless a real on-disk directory is provided,
// so `tass init / scan / policy` all work out of the box on any machine.
func buildASTScanner(rulesDir string) (*scanner.ASTScanner, error) {
	useEmbedded := rulesDir == "" || rulesDir == "./rules"

	if !useEmbedded {
		// Explicit custom path — use disk.
		s, err := scanner.NewASTScannerFromDir(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("load rules from %s: %w", rulesDir, err)
		}
		return s, nil
	}

	// Default path: check if ./rules actually exists (dev environment).
	if _, err := os.Stat(rulesDir); err == nil {
		s, diskErr := scanner.NewASTScannerFromDir(rulesDir)
		if diskErr == nil {
			slog.Debug("rules: loaded from disk", "dir", rulesDir)
			return s, nil
		}
		slog.Warn("rules: disk load failed, falling back to embedded", "err", diskErr)
	}

	// Fall back to embedded rules bundled in the binary.
	s, err := scanner.NewASTScannerFromFS(tass.RulesFS())
	if err != nil {
		return nil, fmt.Errorf("load embedded rules: %w", err)
	}
	slog.Debug("rules: using embedded rules")
	return s, nil
}
