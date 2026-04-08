// Package tass provides the embedded tree-sitter detection rules bundled into
// the binary at build time. Placing this file at the module root is the only
// way to embed the sibling rules/ directory without using ".." in the path
// (which Go's embed directive prohibits).
package tass

import (
	"embed"
	"io/fs"
)

//go:embed rules
var rulesFS embed.FS

// RulesFS returns a sub-FS rooted at the embedded rules/ directory so callers
// see language subdirectories ("go/", "python/", "javascript/") at the top level.
func RulesFS() fs.FS {
	sub, err := fs.Sub(rulesFS, "rules")
	if err != nil {
		panic("embedrules: sub-FS: " + err.Error())
	}
	return sub
}
