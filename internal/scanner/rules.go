package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gopkg.in/yaml.v3"
)

// knownLanguages maps rules subdirectory names to language identifiers.
// Add a new entry here when support for an additional language is added,
// along with a corresponding case in grammarForLang.
var knownLanguages = map[string]string{
	"go":         "go",
	"python":     "python",
	"javascript": "javascript",
}

// LoadRules walks rulesDir, loads every .scm file that has a .meta.yaml sidecar,
// compiles each query against the appropriate grammar, and returns a map of
// language → compiled rules.
//
// Rules without a .meta.yaml sidecar are skipped with a warning.
// Rules with an empty or missing symbol_capture field are skipped with an error log.
// Unknown language directories are skipped silently.
func LoadRules(rulesDir string) (map[string][]*Rule, error) {
	result := make(map[string][]*Rule)

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("rules.LoadRules: read dir %q: %w", rulesDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		lang, ok := knownLanguages[entry.Name()]
		if !ok {
			slog.Debug("rules: skipping unknown language directory", "dir", entry.Name())
			continue
		}

		grammar := grammarForLang(lang)
		if grammar == nil {
			slog.Warn("rules: no grammar registered for language", "lang", lang)
			continue
		}

		langDir := filepath.Join(rulesDir, entry.Name())
		rules, err := loadLangRules(langDir, lang, grammar)
		if err != nil {
			return nil, fmt.Errorf("rules.LoadRules: language %q: %w", lang, err)
		}
		if len(rules) > 0 {
			result[lang] = append(result[lang], rules...)
		}
	}

	return result, nil
}

// loadLangRules loads all rules from a single language directory.
func loadLangRules(dir, lang string, grammar *sitter.Language) ([]*Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", dir, err)
	}

	var rules []*Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".scm") {
			continue
		}

		ruleName := strings.TrimSuffix(entry.Name(), ".scm")
		scmPath := filepath.Join(dir, entry.Name())
		metaPath := filepath.Join(dir, ruleName+".meta.yaml")

		// Load query source.
		queryBytes, err := os.ReadFile(scmPath)
		if err != nil {
			return nil, fmt.Errorf("read query %q: %w", scmPath, err)
		}

		// Load metadata sidecar — required.
		metaBytes, err := os.ReadFile(metaPath)
		if err != nil {
			slog.Warn("rules: missing .meta.yaml for rule, skipping",
				"rule", scmPath, "expected", metaPath)
			continue
		}

		var meta RuleMeta
		if err := yaml.Unmarshal(metaBytes, &meta); err != nil {
			return nil, fmt.Errorf("parse meta %q: %w", metaPath, err)
		}

		if meta.SymbolCapture == "" {
			slog.Error("rules: rule has empty symbol_capture, skipping",
				"rule", scmPath)
			continue
		}
		if meta.CapID == "" {
			slog.Error("rules: rule has empty cap_id, skipping", "rule", scmPath)
			continue
		}
		if meta.Confidence <= 0 {
			slog.Error("rules: rule has zero confidence, skipping", "rule", scmPath)
			continue
		}

		// Compile the tree-sitter query against the language grammar.
		query, err := sitter.NewQuery(queryBytes, grammar)
		if err != nil {
			return nil, fmt.Errorf("compile query %q: %w", scmPath, err)
		}

		rules = append(rules, &Rule{
			Query:    query,
			Meta:     meta,
			Language: lang,
			Name:     ruleName,
		})

		slog.Debug("rules: loaded rule", "lang", lang, "rule", ruleName,
			"category", meta.Category, "confidence", meta.Confidence)
	}

	return rules, nil
}

// NewASTScannerFromDir constructs an ASTScanner by loading all rules from rulesDir.
// This is the production constructor used by the CLI and webhook handler.
func NewASTScannerFromDir(rulesDir string) (*ASTScanner, error) {
	rules, err := LoadRules(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("scanner.NewASTScannerFromDir: %w", err)
	}
	return NewASTScanner(rules), nil
}
