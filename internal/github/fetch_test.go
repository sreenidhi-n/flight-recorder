package github_test

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	gh "github.com/tass-security/tass/internal/github"
)

func TestBase64DecodeWithNewlines(t *testing.T) {
	// GitHub's contents API wraps base64 with newlines every 60 chars.
	// Verify our strip+decode logic handles this correctly.
	content := []byte("module github.com/example/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/stripe/stripe-go/v76 v76.0.0\n)\n")
	encoded := base64.StdEncoding.EncodeToString(content)

	// Simulate GitHub's wrapping
	wrapped := wrapAtWidth(encoded, 60)

	// Strip newlines and decode
	stripped := stripNL(wrapped)
	decoded, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(content) {
		t.Errorf("round-trip failed:\ngot:  %q\nwant: %q", decoded, content)
	}
}

func TestKnownDepFilenames(t *testing.T) {
	depFilenames := gh.KnownDepFilenames()

	expected := []string{"go.mod", "requirements.txt", "package.json"}
	for _, name := range expected {
		if _, ok := depFilenames[name]; !ok {
			t.Errorf("KnownDepFilenames: missing %q", name)
		}
	}

	unexpected := []string{"go.sum", "Cargo.toml", "Gemfile", "pom.xml"}
	for _, name := range unexpected {
		if _, ok := depFilenames[name]; ok {
			t.Errorf("KnownDepFilenames: unexpected %q", name)
		}
	}
}

func TestKnownSourceExts(t *testing.T) {
	sourceExts := gh.KnownSourceExts()

	expected := []string{".go", ".py", ".js"}
	for _, ext := range expected {
		if _, ok := sourceExts[ext]; !ok {
			t.Errorf("KnownSourceExts: missing %q", ext)
		}
	}

	unexpected := []string{".md", ".yaml", ".json", ".sum"}
	for _, ext := range unexpected {
		if _, ok := sourceExts[ext]; ok {
			t.Errorf("KnownSourceExts: unexpected %q", ext)
		}
	}
}

func TestPRFileFiltering(t *testing.T) {
	depFilenames := gh.KnownDepFilenames()
	sourceExts := gh.KnownSourceExts()

	tests := []struct {
		filename string
		isDep    bool
		isSource bool
	}{
		{"go.mod", true, false},
		{"requirements.txt", true, false},
		{"package.json", true, false},
		{"cmd/main.go", false, true},
		{"app.py", false, true},
		{"src/index.js", false, true},
		{"src/worker.mjs", false, true},
		{"README.md", false, false},
		{"Dockerfile", false, false},
		{"go.sum", false, false},
		{".github/workflows/ci.yaml", false, false},
	}

	for _, tt := range tests {
		base := filepath.Base(tt.filename)
		ext := filepath.Ext(tt.filename)

		_, isDep := depFilenames[base]
		_, isSource := sourceExts[ext]

		if isDep != tt.isDep {
			t.Errorf("%s: isDep = %v, want %v", tt.filename, isDep, tt.isDep)
		}
		if isSource != tt.isSource {
			t.Errorf("%s: isSource = %v, want %v", tt.filename, isSource, tt.isSource)
		}
	}
}

// Compile-check that Pipeline and its types are reachable
var _ = context.Background
var _ *gh.App

// --- helpers ---

func wrapAtWidth(s string, width int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

func stripNL(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c != '\n' && c != '\r' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
