package scanner

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
)

// grammarForLang returns the tree-sitter language grammar for the given language
// identifier. Returns nil for unknown languages.
// Add new cases here when support for additional languages is added.
func grammarForLang(lang string) *sitter.Language {
	switch lang {
	case "go":
		return golang.GetLanguage()
	case "python":
		return python.GetLanguage()
	case "javascript":
		return javascript.GetLanguage()
	default:
		return nil
	}
}
