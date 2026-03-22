// Package scanner provides the capability detection engine:
// Layer 0 (dependency file diffing) and Layer 1 (Tree-sitter AST queries).
package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
)

// skipDirs is the set of directory names to skip during repo walks.
// These directories contain generated, vendored, or non-project code.
var skipDirs = map[string]bool{
	".git":        true,
	"vendor":      true,
	"node_modules": true,
	"__pycache__": true,
	".venv":       true,
	"venv":        true,
	"dist":        true,
	"build":       true,
	".cache":      true,
}

// extToLang maps source file extensions to tree-sitter language identifiers.
var extToLang = map[string]string{
	".go":  "go",
	".py":  "python",
	".js":  "javascript",
	".mjs": "javascript",
	".cjs": "javascript",
}

// Scanner is the unified detection engine. It combines Layer 0 (dependency
// file diffing) and Layer 1 (Tree-sitter AST queries) into a single pipeline
// that produces a CapabilitySet.
type Scanner struct {
	registry   map[string]DepParser // dep filename → parser
	astScanner *ASTScanner          // nil = Layer 1 disabled
}

// New creates a Scanner. Pass nil for astScanner to run Layer 0 only.
func New(registry map[string]DepParser, astScanner *ASTScanner) *Scanner {
	return &Scanner{
		registry:   registry,
		astScanner: astScanner,
	}
}

// ScanRepo performs a full scan of a local repository: all dependency files
// (Layer 0) and all source files (Layer 1). Used by `tass init` and dogfooding.
func (s *Scanner) ScanRepo(repoRoot string) (*contracts.CapabilitySet, error) {
	seen := make(map[string]struct{})
	var caps []contracts.Capability

	// --- Layer 0: dependency files ---
	l0caps, err := s.scanRepoDeps(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("scanner.ScanRepo: layer0: %w", err)
	}
	for _, c := range l0caps {
		seen[c.ID] = struct{}{}
		caps = append(caps, c)
	}

	// --- Layer 1: AST scan ---
	if s.astScanner != nil {
		l1caps, err := s.scanRepoAST(repoRoot)
		if err != nil {
			return nil, fmt.Errorf("scanner.ScanRepo: layer1: %w", err)
		}
		for _, c := range l1caps {
			// Layer 0 wins on ID collision.
			if _, dup := seen[c.ID]; !dup {
				seen[c.ID] = struct{}{}
				caps = append(caps, c)
			}
		}
	}

	return &contracts.CapabilitySet{
		RepoRoot:     repoRoot,
		ScanTime:     time.Now().UTC(),
		Capabilities: caps,
	}, nil
}

// ScanDiff performs a diff scan: only capabilities introduced by the changes
// between baseBranch and HEAD. Used by `tass scan` for local development.
//
// It uses git to enumerate changed files and fetch base-branch content.
// Arguments are passed as separate exec.Command args — no shell injection risk.
//
// In production (Phase 3), ScanRemote replaces this for webhook-triggered scans.
func (s *Scanner) ScanDiff(repoRoot, baseBranch string) (*contracts.CapabilitySet, error) {
	changedFiles, err := gitChangedFiles(repoRoot, baseBranch)
	if err != nil {
		return nil, fmt.Errorf("scanner.ScanDiff: %w", err)
	}

	if len(changedFiles) == 0 {
		slog.Info("scanner.ScanDiff: no changed files", "base", baseBranch)
		return &contracts.CapabilitySet{
			RepoRoot:     repoRoot,
			ScanTime:     time.Now().UTC(),
			Capabilities: nil,
		}, nil
	}

	seen := make(map[string]struct{})
	var caps []contracts.Capability

	// --- Layer 0: diff changed dependency files ---
	for _, relFile := range changedFiles {
		filename := filepath.Base(relFile)
		parser, ok := s.registry[filename]
		if !ok {
			continue
		}

		baseContent, err := gitShowFile(repoRoot, baseBranch, relFile)
		if err != nil {
			slog.Warn("scanner.ScanDiff: could not fetch base content, treating as new file",
				"file", relFile, "err", err)
			baseContent = nil
		}

		prContent, err := os.ReadFile(filepath.Join(repoRoot, relFile))
		if err != nil {
			slog.Warn("scanner.ScanDiff: could not read PR file, skipping",
				"file", relFile, "err", err)
			continue
		}

		added, _, err := DiffDependencies(baseContent, prContent, parser)
		if err != nil {
			slog.Warn("scanner.ScanDiff: dep diff failed, skipping",
				"file", relFile, "err", err)
			continue
		}

		for _, c := range added {
			if _, dup := seen[c.ID]; !dup {
				seen[c.ID] = struct{}{}
				c.Location.File = relFile
				caps = append(caps, c)
			}
		}
	}

	// --- Layer 1: AST scan changed source files ---
	if s.astScanner != nil {
		for _, relFile := range changedFiles {
			lang, ok := extToLang[strings.ToLower(filepath.Ext(relFile))]
			if !ok {
				continue
			}

			content, err := os.ReadFile(filepath.Join(repoRoot, relFile))
			if err != nil {
				slog.Warn("scanner.ScanDiff: could not read source file, skipping",
					"file", relFile, "err", err)
				continue
			}

			fileCaps, err := s.astScanner.ScanBytes(content, relFile, lang)
			if err != nil {
				slog.Warn("scanner.ScanDiff: AST scan failed, skipping",
					"file", relFile, "err", err)
				continue
			}

			for _, c := range fileCaps {
				if _, dup := seen[c.ID]; !dup {
					seen[c.ID] = struct{}{}
					caps = append(caps, c)
				}
			}
		}
	}

	return &contracts.CapabilitySet{
		RepoRoot:     repoRoot,
		ScanTime:     time.Now().UTC(),
		Capabilities: caps,
	}, nil
}

// ScanRemote scans files provided as raw bytes — the primary path for Phase 3
// webhook-triggered scans where files are fetched from the GitHub API.
//
// headFiles: map of repo-relative path → current file content (changed files only).
// baseDeps: map of dep file path → base branch content (nil value = new file in PR).
//
// Because DepParser and ASTScanner both operate on []byte, this implementation
// is straightforward and requires no filesystem access.
func (s *Scanner) ScanRemote(headFiles, baseDeps map[string][]byte) (*contracts.CapabilitySet, error) {
	// Phase 3: implement in Step 3.4 (webhook handler).
	// The signature is load-bearing — do not change it.
	return nil, fmt.Errorf("scanner.ScanRemote: not yet implemented (Phase 3)")
}

// --- internal helpers ---

// scanRepoDeps walks repoRoot and parses all known dependency files (Layer 0).
func (s *Scanner) scanRepoDeps(repoRoot string) ([]contracts.Capability, error) {
	var caps []contracts.Capability
	seen := make(map[string]struct{})

	for filename, parser := range s.registry {
		err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skipDirs[d.Name()] || (len(d.Name()) > 0 && d.Name()[0] == '.') {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Name() != filename {
				return nil
			}

			fileCaps, err := scanner_parseFile(parser, path)
			if err != nil {
				slog.Warn("scanner: dep parse failed, skipping", "file", path, "err", err)
				return nil
			}

			rel := relPath(repoRoot, path)
			for _, c := range fileCaps {
				if _, dup := seen[c.ID]; !dup {
					seen[c.ID] = struct{}{}
					c.Location.File = rel
					caps = append(caps, c)
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk for %s: %w", filename, err)
		}
	}

	return caps, nil
}

// scanRepoAST walks repoRoot and AST-scans all known source files (Layer 1).
func (s *Scanner) scanRepoAST(repoRoot string) ([]contracts.Capability, error) {
	var caps []contracts.Capability
	seen := make(map[string]struct{})

	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || (len(d.Name()) > 0 && d.Name()[0] == '.') {
				return filepath.SkipDir
			}
			return nil
		}

		lang, ok := extToLang[strings.ToLower(filepath.Ext(path))]
		if !ok {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("scanner: source read failed, skipping", "file", path, "err", err)
			return nil
		}

		rel := relPath(repoRoot, path)
		fileCaps, err := s.astScanner.ScanBytes(content, rel, lang)
		if err != nil {
			slog.Warn("scanner: AST scan failed, skipping", "file", path, "err", err)
			return nil
		}

		for _, c := range fileCaps {
			if _, dup := seen[c.ID]; !dup {
				seen[c.ID] = struct{}{}
				caps = append(caps, c)
			}
		}
		return nil
	})

	return caps, err
}

// gitChangedFiles returns the list of files changed between baseBranch and HEAD
// using `git diff --name-only baseBranch...HEAD`. Paths are repo-relative.
func gitChangedFiles(repoRoot, baseBranch string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoRoot, "diff", "--name-only",
		baseBranch+"...HEAD")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}

	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// gitShowFile fetches a file's content at a given ref using `git show ref:path`.
// Returns nil, nil if the file did not exist at that ref (new file in PR).
func gitShowFile(repoRoot, ref, relPath string) ([]byte, error) {
	cmd := exec.Command("git", "-C", repoRoot, "show", ref+":"+relPath)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		// Exit code 128 = file not found at ref (new file). Treat as nil base.
		return nil, nil //nolint:nilerr
	}
	return out, nil
}

// scanner_parseFile is a package-internal wrapper around ParseFile to avoid
// a name collision with the exported ParseFile in depparser.go.
func scanner_parseFile(p DepParser, path string) ([]contracts.Capability, error) {
	return ParseFile(p, path)
}

// relPath returns path relative to base, or path unchanged if that fails.
func relPath(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}
