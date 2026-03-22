package scanner

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

// grammarForLang returns the tree-sitter language grammar for the given language
// identifier. Returns nil for unknown languages.
// Step 2.4 adds Python and JavaScript grammars.
func grammarForLang(lang string) *sitter.Language {
	switch lang {
	case "go":
		return golang.GetLanguage()
	default:
		return nil
	}
}
