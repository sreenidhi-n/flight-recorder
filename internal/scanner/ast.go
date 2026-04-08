package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/tass-security/tass/pkg/contracts"
)

// RuleMeta holds the metadata loaded from a .meta.yaml sidecar file.
// It defines the detection rule's semantics: what category it represents,
// a human-readable name, confidence score, and how to construct the capability ID.
type RuleMeta struct {
	// Category maps to a contracts.CapCategory (e.g., "network_access").
	Category contracts.CapCategory `yaml:"category"`
	// Name is a short human-readable description of what this rule detects.
	Name string `yaml:"name"`
	// Confidence is the detection confidence score (0.0–1.0).
	Confidence float64 `yaml:"confidence"`
	// CapID is the prefix used to construct the final capability ID.
	// Final ID formula: ast:{lang}:{cap_id}:{matched_identifier}
	// Example: cap_id "net/http:client" + matched "Post" → ast:go:net/http:client:Post
	CapID string `yaml:"cap_id"`
	// SymbolCapture is the name of the tree-sitter capture that contains the
	// matched symbol (e.g., "method", "func", "callee"). The text of this
	// capture becomes the {matched_identifier} in the capability ID.
	// Every rule MUST define this field — rules without it are rejected at load time.
	SymbolCapture string `yaml:"symbol_capture"`
}

// Rule is a compiled, ready-to-execute detection rule.
type Rule struct {
	// Query is the compiled tree-sitter query.
	Query *sitter.Query
	// Meta holds the rule's metadata (category, name, confidence, ID prefix).
	Meta RuleMeta
	// Language is the language this rule targets (e.g., "go", "python", "javascript").
	Language string
	// Name is the rule's filename stem (e.g., "http_client"), used for logging.
	Name string
}

// ASTScanner runs tree-sitter queries against source file content and returns
// detected capabilities. It is the Layer 1 detection engine.
//
// The tree-sitter parser is stateful and cannot be used concurrently, so
// ScanBytes serialises calls via a mutex. For high-throughput use a sync.Pool
// of parsers instead, but the mutex is sufficient for the current workload.
type ASTScanner struct {
	mu     sync.Mutex
	parser *sitter.Parser
	// rules maps language name → list of compiled rules for that language.
	rules map[string][]*Rule
}

// NewASTScanner creates an ASTScanner with a pre-built rule map.
// Use NewASTScannerFromDir to load rules from the filesystem.
func NewASTScanner(rules map[string][]*Rule) *ASTScanner {
	return &ASTScanner{
		parser: sitter.NewParser(),
		rules:  rules,
	}
}

// ScanBytes is the primary interface — it scans raw file content and returns
// detected capabilities. It works on both local files and content fetched via
// the GitHub API, making it Phase 3 ready without any changes.
//
// content is the raw source file bytes.
// filename is used to populate the capability's Location field.
// lang is the language identifier ("go", "python", "javascript").
func (s *ASTScanner) ScanBytes(content []byte, filename, lang string) ([]contracts.Capability, error) {
	langRules, ok := s.rules[lang]
	if !ok || len(langRules) == 0 {
		return nil, nil
	}

	grammar := grammarForLang(lang)
	if grammar == nil {
		return nil, fmt.Errorf("ast: no grammar registered for language %q", lang)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.parser.SetLanguage(grammar)
	tree, err := s.parser.ParseCtx(context.Background(), nil, content)
	if err != nil {
		return nil, fmt.Errorf("ast: parse %q: %w", filename, err)
	}
	defer tree.Close()

	root := tree.RootNode()
	var caps []contracts.Capability
	// seen deduplicates by capability ID within a single file scan.
	seen := make(map[string]struct{})

	for _, rule := range langRules {
		cursor := sitter.NewQueryCursor()
		cursor.Exec(rule.Query, root)

		for {
			match, ok := cursor.NextMatch()
			if !ok {
				break
			}

			// go-tree-sitter's NextMatch does not automatically apply #match?/#eq?
			// predicates — FilterPredicates evaluates them against the source bytes.
			match = cursor.FilterPredicates(match, content)
			if len(match.Captures) == 0 {
				continue
			}

			// Extract the symbol capture that drives the ID.
			symbol := captureText(match.Captures, rule.Meta.SymbolCapture, rule.Query, content)
			if symbol == "" {
				continue
			}

			capID := fmt.Sprintf("ast:%s:%s:%s", lang, rule.Meta.CapID, symbol)
			if _, dup := seen[capID]; dup {
				continue
			}
			seen[capID] = struct{}{}

			// Use the symbol capture node's position for the location.
			loc := captureLocation(match.Captures, rule.Meta.SymbolCapture, rule.Query, filename)

			caps = append(caps, contracts.Capability{
				ID:          capID,
				Name:        fmt.Sprintf("%s (%s)", rule.Meta.Name, symbol),
				Category:    rule.Meta.Category,
				Source:      contracts.LayerAST,
				Location:    loc,
				Confidence:  rule.Meta.Confidence,
				RawEvidence: symbol,
			})
		}
	}

	return caps, nil
}

// ScanFile is a convenience wrapper for local filesystem use.
// For content fetched via the GitHub API, use ScanBytes directly.
func (s *ASTScanner) ScanFile(path, lang string) ([]contracts.Capability, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ast.ScanFile: read %q: %w", path, err)
	}
	return s.ScanBytes(content, path, lang)
}

// captureText returns the source text of the first capture with the given name.
func captureText(captures []sitter.QueryCapture, name string, q *sitter.Query, src []byte) string {
	for _, c := range captures {
		if q.CaptureNameForId(c.Index) == name {
			return c.Node.Content(src)
		}
	}
	return ""
}

// captureLocation returns a CodeLocation for the first capture with the given name.
func captureLocation(captures []sitter.QueryCapture, name string, q *sitter.Query, filename string) contracts.CodeLocation {
	for _, c := range captures {
		if q.CaptureNameForId(c.Index) == name {
			node := c.Node
			return contracts.CodeLocation{
				File:   filename,
				Line:   int(node.StartPoint().Row) + 1, // tree-sitter rows are 0-indexed
				Column: int(node.StartPoint().Column) + 1,
			}
		}
	}
	return contracts.CodeLocation{File: filename}
}
