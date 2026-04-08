package tassignore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tass-security/tass/pkg/tassignore"
)

func makeIgnoreFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, ".tassignore"), []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBasicGlob(t *testing.T) {
	dir := makeIgnoreFile(t, "*.test.js\n")
	m, err := tassignore.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.ShouldIgnore("foo.test.js") {
		t.Error("expected foo.test.js to be ignored")
	}
	if m.ShouldIgnore("foo.js") {
		t.Error("expected foo.js NOT to be ignored")
	}
}

func TestDirectoryPattern(t *testing.T) {
	dir := makeIgnoreFile(t, "vendor/\n")
	m, _ := tassignore.Load(dir)
	if !m.ShouldIgnore("vendor/pkg/mod.go") {
		t.Error("expected vendor/pkg/mod.go to be ignored")
	}
	if !m.ShouldIgnore("vendor/foo.go") {
		t.Error("expected vendor/foo.go to be ignored")
	}
	if m.ShouldIgnore("foo.go") {
		t.Error("expected foo.go NOT to be ignored")
	}
}

func TestNegationPattern(t *testing.T) {
	dir := makeIgnoreFile(t, "*.go\n!main.go\n")
	m, _ := tassignore.Load(dir)
	if !m.ShouldIgnore("util.go") {
		t.Error("expected util.go to be ignored by *.go")
	}
	if m.ShouldIgnore("main.go") {
		t.Error("expected main.go NOT to be ignored due to negation")
	}
}

func TestNoIgnoreFile(t *testing.T) {
	dir := t.TempDir() // no .tassignore
	m, err := tassignore.Load(dir)
	if err != nil {
		t.Fatalf("unexpected error for missing file: %v", err)
	}
	if m.ShouldIgnore("anything.go") {
		t.Error("expected nothing to be ignored when no .tassignore exists")
	}
}

func TestCommentsAndBlankLines(t *testing.T) {
	dir := makeIgnoreFile(t, `
# this is a comment
*.spec.js

# another comment
vendor/
`)
	m, _ := tassignore.Load(dir)
	if !m.ShouldIgnore("foo.spec.js") {
		t.Error("expected foo.spec.js to be ignored")
	}
	if m.ShouldIgnore("foo.js") {
		t.Error("expected foo.js NOT to be ignored")
	}
	if !m.ShouldIgnore("vendor/lib/a.go") {
		t.Error("expected vendor/lib/a.go to be ignored")
	}
}

func TestDoubleStarGlob(t *testing.T) {
	dir := makeIgnoreFile(t, "**/*.spec.py\n")
	m, _ := tassignore.Load(dir)
	if !m.ShouldIgnore("tests/unit/foo.spec.py") {
		t.Error("expected tests/unit/foo.spec.py to be ignored")
	}
	if !m.ShouldIgnore("foo.spec.py") {
		t.Error("expected foo.spec.py to be ignored")
	}
	if m.ShouldIgnore("foo.py") {
		t.Error("expected foo.py NOT to be ignored")
	}
}

func TestLoadBytes(t *testing.T) {
	m := tassignore.LoadBytes([]byte("*.log\nnode_modules/\n"))
	if !m.ShouldIgnore("app.log") {
		t.Error("expected app.log to be ignored")
	}
	if !m.ShouldIgnore("node_modules/pkg/index.js") {
		t.Error("expected node_modules path to be ignored")
	}
	if m.ShouldIgnore("main.go") {
		t.Error("expected main.go NOT to be ignored")
	}
}

func TestUnderscoreTestFiles(t *testing.T) {
	dir := makeIgnoreFile(t, "*_test.go\n")
	m, _ := tassignore.Load(dir)
	if !m.ShouldIgnore("storage_test.go") {
		t.Error("expected storage_test.go to be ignored")
	}
	if m.ShouldIgnore("storage.go") {
		t.Error("expected storage.go NOT to be ignored")
	}
}
